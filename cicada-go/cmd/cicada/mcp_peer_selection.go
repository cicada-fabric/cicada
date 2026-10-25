package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"reflect"
	"strings"
	"time"

	"github.com/cicada-ai/cicada/internal/fabric"
	"github.com/cicada-ai/cicada/internal/harness"
)

var errMCPPeerSelection = errors.New("PEER_SELECTION_INVALID: select an exact currently authorized peer again")
var errMCPPeerStale = errors.New("PEER_SELECTION_STALE: original actor, scope, peer binding or directory permission changed")

type mcpPeerSelection struct {
	ID, Scope, ScopeID, SourceDigest string
	Native                           mcpTrustedContext
	SourceEndpoint                   string
	GroupScope                       mcpOutboxScope
	Target                           fabric.NetworkCard
	NetworkTarget                    fabric.NetworkEndpointCard
	Expires                          time.Time
}

func validateMCPPeerArguments(name string, args map[string]any) (bool, error) {
	if name == "cicada_select_peer" {
		for key, value := range args {
			if key != "scope" && key != "network_id" && key != "query" {
				return true, errMCPPeerSelection
			}
			if _, ok := value.(string); !ok {
				return true, errMCPPeerSelection
			}
		}
		scope := stringArgument(args, "scope")
		network := stringArgument(args, "network_id")
		if scope != "group" && scope != "network" || scope == "group" && network != "" || scope == "network" && !validNetworkRouteID(network) || len(stringArgument(args, "query")) > 128 {
			return true, errMCPPeerSelection
		}
		return true, nil
	}
	if name == "cicada_send" || name == "cicada_ask" {
		if value, exists := args["peer_selection_id"]; exists {
			id, ok := value.(string)
			if !ok || !localContextText(id, 64) {
				return true, errMCPPeerSelection
			}
			for _, key := range []string{"target", "link_id", "network_id", "data_scope"} {
				if _, exists := args[key]; exists {
					return true, errMCPPeerSelection
				}
			}
		}
	}
	return false, nil
}

func (m *mcpServer) peerNative() (harness.SessionContext, mcpTrustedContext, error) {
	native, err := m.detectCurrentCodexSession()
	if err != nil {
		return native, mcpTrustedContext{}, err
	}
	trusted, err := normalizeMCPTrustedContext(native)
	return native, trusted, err
}

func peerDigest(value any) string { raw, _ := json.Marshal(value); return localNodeDigest(raw) }

func (m *mcpServer) groupPeerSource() (mcpOutboxScope, string, error) {
	scope, err := m.currentMCPOutboxScope()
	if err != nil {
		return scope, "", err
	}
	value, err := m.api(http.MethodGet, "/v2/fabric/whoami", nil)
	if err != nil {
		return scope, "", err
	}
	card, err := networkCardFromResult(value)
	if err != nil || card.EndpointID != scope.EndpointID || card.GroupID != scope.GroupID || card.NodeID != scope.NodeID || card.NativeSessionID != scope.NativeSessionID || card.BindingID == "" || card.BindingEpoch == 0 {
		return scope, "", errMCPPeerStale
	}
	return scope, peerDigest([]any{scope, card.PrincipalID, card.BindingID, card.BindingEpoch}), nil
}

func (m *mcpServer) withPeerNetwork(network string, recover bool, fn func(harness.SessionContext, networkCLIState) (any, error)) (any, error) {
	if m.localNode != nil {
		return m.withTrustedNodeNetwork(network, recover, fn)
	}
	native, _, err := m.peerNative()
	if err != nil {
		return nil, err
	}
	scope, _, err := mcpSessionScope(m.baseURL, native)
	if err != nil {
		return nil, err
	}
	dir, err := privateNetworkScopeDir(os.Getenv("CICADA_NETWORK_SESSION_DIR"), scope, false)
	if err != nil {
		return nil, errMCPNetworkSelection
	}
	path, err := mcpNetworkFile(dir, network, ".session.json")
	if err != nil {
		return nil, err
	}
	lock, err := lockNetworkMCPState(path)
	if err != nil {
		return nil, err
	}
	defer lock.Unlock()
	raw, err := readPrivateNetworkFile(path, 16<<10)
	var state networkCLIState
	if err != nil || decodeLocalNodeJSON(raw, &state) != nil || state.Version != 1 || state.APIOrigin != m.baseURL || state.NetworkID != network || state.EndpointID == "" || state.SessionToken == "" || state.Harness != native.Harness || state.NativeSessionID != native.NativeSessionID || state.NodeID != native.MachineID || state.Workspace != native.Workspace {
		return nil, errMCPNetworkSelection
	}
	return fn(native, state)
}

// All displayed metadata is a projection of the current authorized directory,
// never an Owner inventory. Endpoint ID disambiguates duplicate names; opaque
// option IDs are the only values accepted back from the Host form.
func (m *mcpServer) selectPeer(args map[string]any) (any, error) {
	if m.stdio == nil || !m.stdio.supportsPeerForm() {
		return nil, errors.New("PEER_FORM_UNSUPPORTED: this Host has no form transport")
	}
	_, native, err := m.peerNative()
	if err != nil {
		return nil, err
	}
	selection := mcpPeerSelection{Scope: stringArgument(args, "scope"), ScopeID: stringArgument(args, "network_id"), Native: native, Expires: time.Now().Add(120 * time.Second)}
	query := strings.ToLower(stringArgument(args, "query"))
	options := []mcpPeerFormOption{}
	choices := map[string]mcpPeerSelection{}
	add := func(choice mcpPeerSelection, label string) error {
		if len(options) >= 64 {
			return nil
		}
		id, err := newMCPOutboxID("peeroption")
		if err != nil {
			return err
		}
		options = append(options, mcpPeerFormOption{ID: id, Label: label})
		choices[id] = choice
		return nil
	}
	if selection.Scope == "group" {
		scope, digest, err := m.groupPeerSource()
		if err != nil {
			return nil, err
		}
		selection.ScopeID, selection.SourceEndpoint, selection.GroupScope, selection.SourceDigest = scope.GroupID, scope.EndpointID, scope, digest
		value, err := m.api(http.MethodGet, "/v2/fabric/list?limit=64", nil)
		if err != nil {
			return nil, err
		}
		raw, _ := json.Marshal(value)
		var page struct {
			Endpoints []fabric.NetworkCard `json:"endpoints"`
		}
		if json.Unmarshal(raw, &page) != nil || page.Endpoints == nil || len(page.Endpoints) > 64 {
			return nil, errMCPPeerSelection
		}
		for _, card := range page.Endpoints {
			if card.EndpointID == scope.EndpointID || card.EndpointID == "" || card.GroupID != scope.GroupID || card.NativeSessionID != "" {
				continue
			}
			if query != "" && !strings.Contains(strings.ToLower(card.Name+" "+card.EndpointID+" "+card.NodeID+" "+card.Workspace), query) {
				continue
			}
			choice := selection
			choice.Target = card
			label := peerContactLabel(card.Name, card.NodeID, card.Workspace, card.Status, card.EndpointID)
			if err := add(choice, label); err != nil {
				return nil, err
			}
		}
	} else {
		_, err := m.withPeerNetwork(selection.ScopeID, true, func(_ harness.SessionContext, state networkCLIState) (any, error) {
			actor, err := m.networkPeerActor(state)
			if err != nil {
				return nil, err
			}
			selection.SourceDigest, selection.SourceEndpoint = networkPeerSourceDigest(actor, state), actor.EndpointID
			value, err := m.networkDirectHTTP(state, http.MethodGet, "/v2/fabric/networks/"+url.PathEscape(state.NetworkID)+"/directory?limit=64", nil)
			if err != nil {
				return nil, err
			}
			raw, _ := json.Marshal(value)
			var page struct {
				Endpoints []fabric.NetworkEndpointCard `json:"endpoints"`
			}
			if json.Unmarshal(raw, &page) != nil || page.Endpoints == nil || len(page.Endpoints) > 64 {
				return nil, errMCPPeerSelection
			}
			for _, card := range page.Endpoints {
				if card.NetworkID != state.NetworkID || card.EndpointID == "" || card.EndpointID == state.EndpointID {
					continue
				}
				if query != "" && !strings.Contains(strings.ToLower(card.Nickname+" "+card.EndpointID), query) {
					continue
				}
				choice := selection
				choice.NetworkTarget = card
				if err := add(choice, peerContactLabel(card.Nickname, "", "", card.Availability, card.EndpointID)); err != nil {
					return nil, err
				}
			}
			return nil, nil
		})
		if err != nil {
			return nil, err
		}
	}
	if len(options) == 0 {
		return nil, errors.New("PEER_DIRECTORY_EMPTY: no matching authorized peer in the first bounded 64-row directory page; this is not a complete-directory absence claim")
	}
	chosen, err := m.stdio.elicitPeer("Choose a contact", options)
	if err != nil {
		return nil, err
	}
	selected, ok := choices[chosen]
	if !ok {
		return nil, errMCPPeerSelection
	}
	if err := m.revalidatePeer(selected); err != nil {
		return nil, err
	}
	id, err := newMCPOutboxID("peerselection")
	if err != nil {
		return nil, err
	}
	selected.ID = id
	m.peerMu.Lock()
	defer m.peerMu.Unlock()
	if m.peerSelections == nil {
		m.peerSelections = map[string]mcpPeerSelection{}
	}
	for key, s := range m.peerSelections {
		if !time.Now().Before(s.Expires) {
			delete(m.peerSelections, key)
		}
	}
	if len(m.peerSelections) >= 64 {
		return nil, errors.New("PEER_SELECTION_LIMIT: too many live selections")
	}
	// Linearize the local reference commit with transport cancellation. An
	// accept may have arrived before a slow final Hub check; that cannot let
	// a cancelled or expired call create a new reference after the check.
	m.stdio.mu.Lock()
	defer m.stdio.mu.Unlock()
	call := m.stdio.active
	if call == nil || call.request.Method != "tools/call" || call.ctx.Err() != nil || m.stdio.ctx.Err() != nil {
		return nil, errMCPFormCancelled
	}
	now := time.Now()
	if !now.Before(selected.Expires) {
		return nil, errMCPPeerStale
	}
	m.peerSelections[id] = selected
	endpoint := selected.Target.EndpointID
	if selected.Scope == "network" {
		endpoint = selected.NetworkTarget.EndpointID
	}
	return map[string]any{"peer_selection_id": id, "scope": selected.Scope, "scope_id": selected.ScopeID, "endpoint_id": endpoint, "binding_id": selected.Target.BindingID, "binding_epoch": selected.Target.BindingEpoch, "expires_at": selected.Expires.UTC().Format(time.RFC3339Nano), "freshness": "SNAPSHOT_ONLY", "directory_bounded": true, "directory_may_have_more": true}, nil
}

func peerLabel(label string) string {
	runes := []rune(strings.Map(func(r rune) rune {
		if r < 32 || r == 127 {
			return ' '
		}
		return r
	}, label))
	if len(runes) > 480 {
		return string(runes[:479]) + "…"
	}
	return string(runes)
}

func peerContactLabel(name, node, workspace, status, id string) string {
	if name == id || name == "" {
		name = "Contact"
	}
	short := func(value string, max int) string {
		runes := []rune(value)
		if len(runes) > max {
			return string(runes[:max-1]) + "…"
		}
		return value
	}
	parts := []string{short(name, 80)}
	if node != "" {
		parts = append(parts, short(node, 48))
	}
	if workspace != "" {
		parts = append(parts, short(workspace, 240))
	}
	if status != "" {
		parts = append(parts, short(status, 24)+" (snapshot)")
	}
	parts = append(parts, fmt.Sprintf("…%s", shortSuffix(id, 8)))
	return peerLabel(strings.Join(parts, " | "))
}

func shortSuffix(value string, size int) string {
	runes := []rune(value)
	if len(runes) > size {
		return string(runes[len(runes)-size:])
	}
	return value
}

func (m *mcpServer) revalidatePeer(s mcpPeerSelection) error {
	if !time.Now().Before(s.Expires) {
		return errMCPPeerStale
	}
	_, native, err := m.peerNative()
	if err != nil || native != s.Native {
		return errMCPPeerStale
	}
	if err := revalidateCodexLocalNode(context.Background(), m.localNode); err != nil {
		return err
	}
	if s.Scope == "group" {
		scope, digest, err := m.groupPeerSource()
		if err != nil || scope != s.GroupScope || digest != s.SourceDigest {
			return errMCPPeerStale
		}
		value, err := m.api(http.MethodPost, "/v2/fabric/resolve", fabric.ResolveInput{Query: s.Target.EndpointID})
		if err != nil {
			return err
		}
		card, err := networkCardFromResult(value)
		if err != nil || card.EndpointID != s.Target.EndpointID || card.GroupID != s.Target.GroupID || card.PrincipalID != s.Target.PrincipalID || card.NodeID != s.Target.NodeID || card.BindingID != s.Target.BindingID || card.BindingEpoch != s.Target.BindingEpoch {
			return errMCPPeerStale
		}
		return nil
	}
	_, err = m.withPeerNetwork(s.ScopeID, false, func(_ harness.SessionContext, state networkCLIState) (any, error) {
		actor, err := m.networkPeerActor(state)
		if err != nil || networkPeerSourceDigest(actor, state) != s.SourceDigest {
			return nil, errMCPPeerStale
		}
		value, err := m.networkDirectHTTP(state, http.MethodPost, "/v2/fabric/networks/"+url.PathEscape(s.ScopeID)+"/resolve", map[string]string{"query": s.NetworkTarget.EndpointID})
		if err != nil {
			return nil, err
		}
		raw, _ := json.Marshal(value)
		var card fabric.NetworkEndpointCard
		if json.Unmarshal(raw, &card) != nil || card.NetworkID != s.ScopeID || card.EndpointID != s.NetworkTarget.EndpointID {
			return nil, errMCPPeerStale
		}
		return nil, nil
	})
	return err
}

func (m *mcpServer) sendSelectedPeer(name string, args map[string]any) (any, error) {
	id := stringArgument(args, "peer_selection_id")
	intent := peerDigest([]any{name, args})
	if result, found, err := m.recoverPeerOutbox(id, intent, stringArgument(args, "idempotency_key")); found || err != nil {
		return result, err
	}
	m.peerMu.Lock()
	selection, ok := m.peerSelections[id]
	m.peerMu.Unlock()
	if !ok {
		return nil, errMCPPeerSelection
	}
	if err := m.revalidatePeer(selection); err != nil {
		return nil, err
	}
	input := mcpOutboxInput{PeerSelectionID: id, PeerIntentDigest: intent, PeerBindingID: selection.Target.BindingID, PeerBindingEpoch: selection.Target.BindingEpoch, Target: selection.Target.EndpointID, Body: stringArgument(args, "body"), Question: stringArgument(args, "question"), ParentRequestID: stringArgument(args, "parent_request_id"), ExpiresAt: stringArgument(args, "expires_at")}
	kind := "send"
	if name == "cicada_ask" {
		kind = "ask"
	}
	if kind == "send" && input.Body == "" {
		input.Body = stringArgument(args, "message")
	}
	if kind == "send" && input.Body == "" || kind == "ask" && input.Question == "" || len(input.Body) > 64<<10 || len(input.Question) > 64<<10 {
		return nil, errMCPPeerSelection
	}
	key := stringArgument(args, "idempotency_key")
	if selection.Scope == "group" {
		if input.ExpiresAt != "" {
			return nil, errMCPPeerSelection
		}
		var err error
		if kind == "send" {
			input.Body, err = m.encodeSelectedGroupSpaceReferences(input.Body, args["record_refs"])
		} else {
			input.Question, err = m.encodeSelectedGroupSpaceReferences(input.Question, args["record_refs"])
		}
		if err != nil {
			return nil, err
		}
		return m.submitMCPOutbox(kind, input, key)
	}
	if args["record_refs"] != nil {
		return nil, errMCPPeerSelection
	}
	return m.withPeerNetwork(selection.ScopeID, false, func(native harness.SessionContext, state networkCLIState) (any, error) {
		input.NetworkID, input.Target = selection.ScopeID, selection.NetworkTarget.EndpointID
		scope, err := m.networkDirectOutboxScope(native, state)
		if err != nil {
			return nil, err
		}
		outbox, err := m.ensureMCPOutbox()
		if err != nil {
			return nil, err
		}
		op, created, err := outbox.prepare(scope, "network_"+kind, key, input)
		if err != nil {
			return nil, err
		}
		if !created {
			return mcpOutboxPublicResult(op), nil
		}
		return m.dispatchMCPNetworkOutbox(outbox, scope, op, native, state)
	})
}

// Recover only the original stored intent, under the original native caller.
// A stale/missing in-memory selection may read that outcome but cannot create
// or redispatch a message. Explicit operation_retry retains original crypto.
func (m *mcpServer) recoverPeerOutbox(id, intent, key string) (any, bool, error) {
	if key == "" {
		return nil, false, nil
	}
	_, native, err := m.peerNative()
	if err != nil {
		return nil, false, err
	}
	outbox, err := m.ensureMCPOutbox()
	if err != nil {
		return nil, false, err
	}
	outbox.mu.Lock()
	defer outbox.mu.Unlock()
	db, err := outbox.withDBLocked()
	if err != nil {
		return nil, false, err
	}
	rows, err := db.Query(`SELECT operation_id,kind,status,api_origin,scope,harness,native_session_id,node_id,workspace,endpoint_id,group_id,network_id,idempotency_key,input_json,input_digest,attempt_count,last_error,result_json,created_at,updated_at,codex_domain_binding FROM mcp_outbox_operations WHERE api_origin=? AND native_session_id=? AND node_id=? AND harness=? AND workspace=? AND idempotency_key=? LIMIT 65`, m.baseURL, native.NativeSessionID, native.NodeID, native.Harness, native.Workspace, key)
	if err != nil {
		return nil, false, err
	}
	defer rows.Close()
	for rows.Next() {
		var op mcpOutboxOperation
		if err := scanMCPOutboxOperation(rows, &op); err != nil {
			return nil, false, err
		}
		var saved mcpOutboxInput
		if json.Unmarshal([]byte(op.InputJSON), &saved) != nil {
			return nil, false, errMCPOutboxPersistence
		}
		if saved.PeerSelectionID != id {
			continue
		}
		if saved.PeerIntentDigest != intent {
			return nil, true, errMCPOutboxConflict
		}
		m.sessionMu.RLock()
		endpoint, group, domain, binding := m.endpointID, m.sessionGroupID, m.sessionDomain, m.sessionPublic
		m.sessionMu.RUnlock()
		if op.GroupID != "" && (op.GroupID != group || op.EndpointID != endpoint) {
			return nil, true, errMCPOutboxContext
		}
		if op.LocalDomainVersion != 0 && (!reflect.DeepEqual(op.codexDomainBinding, domain) || op.NativeBindingID != binding.BindingID || op.NativeBindingEpoch != binding.BindingEpoch) {
			return nil, true, errMCPOutboxContext
		}
		return mcpOutboxPublicResult(op), true, nil
	}
	return nil, false, rows.Err()
}
