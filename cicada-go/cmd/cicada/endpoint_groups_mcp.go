package main

import (
	"context"
	"errors"
	"strings"
	"time"

	"github.com/cicada-ai/cicada/internal/harness"
	wire "github.com/cicada-ai/cicada/internal/hubaccountwire"
	"github.com/cicada-ai/cicada/internal/store"
)

var errEndpointGroupsSelection = errors.New("GROUP_SELECTION_REQUIRED: choose a current Group using cicada_groups and cicada_use_group")

func (m *mcpServer) endpointGroupsRequest(operation, group string) (localEndpointGroupsRequest, error) {
	state := m.codexContext
	if state == nil {
		return localEndpointGroupsRequest{}, errEndpointGroupsUnsupported
	}
	state.mu.RLock()
	defer state.mu.RUnlock()
	if state.active == nil || state.activeVerification == nil || state.activeEndpointGroupsTicketID == "" {
		return localEndpointGroupsRequest{}, errCodexMCPContext
	}
	binding, err := codexContextBinding(*state.activeVerification)
	if err != nil || binding.EndpointGroupsVersion != 1 {
		return localEndpointGroupsRequest{}, errEndpointGroupsUnsupported
	}
	q := localEndpointGroupsRequest{Version: localJoinProtocolVersion, Operation: operation, APIOrigin: m.baseURL, Harness: state.active.Harness, NativeSessionID: state.active.NativeSessionID, Workspace: state.active.Workspace,
		ContextTicketID: state.activeEndpointGroupsTicketID, ConnectionNonce: state.nonce, ToolName: state.activeToolName, ArgumentsDigest: state.activeArgumentsDigest, Arguments: append([]byte(nil), state.activeArguments...), Limit: 64, GroupID: group, codexEndpointGroupsBinding: binding.codexEndpointGroupsBinding}
	if q.ToolName == "cicada_groups" {
		args, err := endpointGroupsBusinessArguments(q.Arguments)
		if err != nil {
			return q, err
		}
		q.Cursor, q.Limit, err = parseEndpointGroupsMCPArguments(args)
		if err != nil {
			return q, err
		}
	}
	return q, nil
}

func (m *mcpServer) endpointGroupsSelf(operation, group string) (*localEndpointGroupsResult, error) {
	q, err := m.endpointGroupsRequest(operation, group)
	if err != nil {
		return nil, err
	}
	result, err := requestMachineAgentEndpointGroups(context.Background(), m.joinSocketPath(harness.SessionContext{MachineID: m.codexContext.nodeID}), q)
	if err != nil {
		return nil, err
	}
	a := result.Description.Registration
	if result.LocalAccessRevision == 0 || result.LocalAccessRevision >= 1<<63 || result.SessionToken == "" || a.Profile != LocalCodexContextProfileEndpointGroups || a.RegistrationSource != wire.EndpointGroupsRegistrationSource || a.Registration.NativeSessionID != q.NativeSessionID || a.Registration.Workspace != q.Workspace || a.Registration.NodeID != m.codexContext.nodeID ||
		a.Registration.Harness != q.Harness || a.RegistrationDigest != q.RegistrationDigest || a.RegistrationRevision != q.RegistrationRevision || a.BindingID != q.RegistrationBindingID || a.BindingEpoch != q.RegistrationBindingEpoch || a.NodeKeyEpoch != q.RegistrationNodeKeyEpoch {
		return nil, errEndpointGroupsRegistration
	}
	return result, nil
}

func (m *mcpServer) refreshEndpointGroupsSession(native harness.SessionContext) (*localEndpointGroupsResult, error) {
	result, err := m.endpointGroupsSelf("endpoint_groups_self", "")
	if err != nil {
		return nil, err
	}
	a := result.Description.Registration
	binding, err := m.currentCodexDomainBinding()
	if err != nil {
		return nil, err
	}
	scope, trusted, err := mcpSessionScope(m.baseURL, native)
	if err != nil {
		return nil, err
	}
	selected := ""
	authority := wire.EndpointGroupCurrentEndpoint{}
	var cached *mcpCachedSession
	if state := m.sessionStateStore(); state != nil {
		cached, err = state.load(m.baseURL, native)
		if err != nil {
			return nil, err
		}
		if cached != nil {
			if validateCodexCachedConnection(cached, m.localNode) != nil || cached.EndpointID != a.Registration.EndpointID || cached.BindingID != a.BindingID || cached.BindingEpoch != a.BindingEpoch || cached.SessionToken != result.SessionToken {
				return nil, errEndpointGroupsRegistration
			}
			if cached.EndpointGroupsVersion == 1 {
				if cached.codexDomainBinding != binding {
					return nil, errCodexMCPContext
				}
				if cached.EndpointGroupsLocalAccessRevision == result.LocalAccessRevision {
					selected, authority = cached.GroupID, cached.EndpointGroupAuthority
				}
			} else if cached.LocalDomainVersion != 1 {
				return nil, errCodexMCPContext
			}
		}
	}
	m.sessionMu.RLock()
	if m.sessionContextSet && m.sessionContext == trusted && m.sessionDomain == binding && m.sessionEndpointGroupsLocalAccessRevision == result.LocalAccessRevision {
		selected, authority = m.sessionGroupID, m.sessionEndpointGroupAuthority
	}
	m.sessionMu.RUnlock()
	if selected != "" {
		found, seen := false, false
		for _, fresh := range result.Description.Authorities {
			if fresh.Relation.GroupID == selected {
				seen = true
				found = fresh == authority
				break
			}
		}
		for _, row := range result.Description.Relations {
			if row.GroupID == selected {
				seen = true
				break
			}
		}
		// A partial page cannot establish absence. A seen changed source/head
		// always clears selection; explicit use_group is required after re-add.
		if !found && (seen || result.Description.Complete) {
			selected = ""
			authority = wire.EndpointGroupCurrentEndpoint{}
		}
	}
	public := mcpPublicJoinResult{Endpoint: store.Endpoint{ID: a.Registration.EndpointID, PrincipalID: a.Registration.PrincipalID, Owner: a.Registration.OwnerID, GroupID: selected, Harness: trusted.Harness, NativeSessionID: trusted.NativeSessionID, MachineID: trusted.NodeID, Workspace: trusted.Workspace}, BindingID: a.BindingID, BindingEpoch: a.BindingEpoch, LeaseExpiresAt: a.LeaseExpiresAt}
	public.NetworkCard.EndpointID = a.Registration.EndpointID
	public.NetworkCard.PrincipalID = a.Registration.PrincipalID
	public.NetworkCard.GroupID = selected
	public.NetworkCard.NodeID = trusted.NodeID
	public.NetworkCard.Harness = trusted.Harness
	public.NetworkCard.NativeSessionID = trusted.NativeSessionID
	public.NetworkCard.Workspace = trusted.Workspace
	public.NetworkCard.BindingID = a.BindingID
	public.NetworkCard.BindingEpoch = a.BindingEpoch
	m.setSession(result.SessionToken, a.Registration.EndpointID, selected, trusted, scope, public)
	m.sessionMu.Lock()
	m.sessionEndpointGroupAuthority = authority
	m.sessionEndpointGroupsLocalAccessRevision = result.LocalAccessRevision
	m.sessionMu.Unlock()
	if err := m.persistEndpointGroupsSession(); err != nil {
		return nil, err
	}
	return result, nil
}

func (m *mcpServer) persistEndpointGroupsSession() error {
	m.sessionMu.RLock()
	t := m.sessionContext
	entry := mcpCachedSession{ConnectionPin: m.localNodePin(), Scope: m.sessionScope, APIOrigin: m.baseURL, Harness: t.Harness, NativeSessionID: t.NativeSessionID, NodeID: t.NodeID, Workspace: t.Workspace, GroupID: m.sessionGroupID, EndpointID: m.endpointID, OwnerID: m.sessionPublic.Endpoint.Owner, BindingID: m.sessionPublic.BindingID, BindingEpoch: m.sessionPublic.BindingEpoch, LeaseExpiresAt: m.sessionPublic.LeaseExpiresAt, SessionToken: m.sessionToken, codexDomainBinding: m.sessionDomain, EndpointGroupAuthority: m.sessionEndpointGroupAuthority, EndpointGroupsLocalAccessRevision: m.sessionEndpointGroupsLocalAccessRevision}
	m.sessionMu.RUnlock()
	if state := m.sessionStateStore(); state != nil {
		return state.saveEndpointGroupsAuthenticated(entry)
	}
	return nil
}

func (m *mcpServer) clearEndpointGroupsSelection() {
	m.sessionMu.Lock()
	if m.sessionDomain.EndpointGroupsVersion == 1 {
		m.sessionGroupID = ""
		m.sessionEndpointGroupAuthority = wire.EndpointGroupCurrentEndpoint{}
		m.sessionPublic.Endpoint.GroupID = ""
		m.sessionPublic.NetworkCard.GroupID = ""
	}
	m.sessionMu.Unlock()
	_ = m.persistEndpointGroupsSession()
}

func (m *mcpServer) useEndpointGroup(group string) (any, error) {
	result, err := m.endpointGroupsSelf("endpoint_groups_select", group)
	if err != nil {
		return nil, err
	}
	if result.Card == nil || result.Authority.Relation.GroupID != group {
		return nil, errEndpointGroupsRegistration
	}
	m.sessionMu.Lock()
	if m.sessionToken != result.SessionToken || m.endpointID != result.Description.Registration.Registration.EndpointID || m.sessionEndpointGroupsLocalAccessRevision != result.LocalAccessRevision {
		m.sessionMu.Unlock()
		return nil, errEndpointGroupsRegistration
	}
	m.sessionGroupID = group
	m.sessionEndpointGroupAuthority = result.Authority
	m.sessionPublic.Endpoint.GroupID = group
	m.sessionPublic.NetworkCard = *result.Card
	m.sessionPublic.LeaseExpiresAt = result.Description.Registration.LeaseExpiresAt
	m.sessionMu.Unlock()
	if err := m.persistEndpointGroupsSession(); err != nil {
		m.clearEndpointGroupsSelection()
		return nil, err
	}
	return *result.Card, nil
}

type endpointGroupsMCPCard struct {
	GroupID          string `json:"group_id"`
	Name             string `json:"name"`
	NetworkID        string `json:"network_id"`
	Current          bool   `json:"current"`
	RelationRevision uint64 `json:"relation_revision"`
	Source           string `json:"source"`
	ExpiresAt        string `json:"expires_at"`
	Freshness        string `json:"freshness"`
}
type endpointGroupsMCPResult struct {
	Groups            []endpointGroupsMCPCard `json:"groups"`
	CurrentGroupID    string                  `json:"current_group_id"`
	SelectionRequired bool                    `json:"selection_required"`
	Complete          bool                    `json:"complete"`
	NextCursor        string                  `json:"next_cursor"`
	Freshness         string                  `json:"freshness"`
}

func (m *mcpServer) endpointGroupsList(arguments map[string]any) (any, error) {
	if _, _, err := parseEndpointGroupsMCPArguments(arguments); err != nil {
		return nil, err
	}
	if m.codexContext == nil {
		return nil, errEndpointGroupsUnsupported
	}
	m.codexContext.mu.RLock()
	fresh := m.codexContext.activeEndpointGroups
	m.codexContext.mu.RUnlock()
	if fresh == nil {
		return nil, errEndpointGroupsUnsupported
	}
	m.sessionMu.RLock()
	selected := m.sessionGroupID
	m.sessionMu.RUnlock()
	r := endpointGroupsMCPResult{Groups: []endpointGroupsMCPCard{}, CurrentGroupID: selected, SelectionRequired: selected == "", Complete: fresh.Description.Complete, NextCursor: fresh.Description.NextCursor, Freshness: "SNAPSHOT_ONLY"}
	for _, card := range fresh.Description.Relations {
		usable := false
		for _, a := range fresh.Description.Authorities {
			if a.Relation.GroupID == card.GroupID {
				usable = true
				break
			}
		}
		if !usable || card.State != "ACTIVE" || card.KeyState != "CURRENT" || card.SelectedSource == nil || card.ExpiresAt != "" && !time.Now().Before(parseMachineNativePairTime(card.ExpiresAt)) {
			continue
		}
		r.Groups = append(r.Groups, endpointGroupsMCPCard{card.GroupID, card.GroupName, card.NetworkID, card.GroupID == selected, card.RelationRevision, card.SelectedSource.Source, card.ExpiresAt, "SNAPSHOT_ONLY"})
	}
	return r, nil
}

func endpointGroupsMCPToolAllowed(name string, arguments map[string]any) bool {
	if stringArgument(arguments, "network_id") != "" || stringArgument(arguments, "link_id") != "" || len(strings.TrimSpace(stringArgument(arguments, "data_scope"))) > 0 {
		return false
	}
	switch name {
	case "cicada_groups", "cicada_use_group", "cicada_whoami", "cicada_members", "cicada_find", "cicada_list", "cicada_resolve", "cicada_inspect", "cicada_select_peer", "cicada_send", "cicada_ask", "cicada_reply", "cicada_receive", "cicada_request_status", "request_status", "cicada_request_cancel", "cicada_cancel", "request_cancel", "cancel", "cicada_operation_status", "cicada_operation_retry", "cicada_outbox_status", "cicada_outbox_retry":
		return true
	}
	return false
}
