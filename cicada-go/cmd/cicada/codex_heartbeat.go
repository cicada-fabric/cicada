package main

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/cicada-ai/cicada/internal/harness"
)

// A worker can renew only this immutable authorized actor. Parent fields are
// consulted solely as an equality fence, never as request identity/credentials.
// Renewal is lease evidence, not proof of the foreground native Thread.
type codexFrozenHeartbeat struct {
	cache             mcpCachedSession
	connection        *LocalNodeConnection
	principal, socket string
	pqtls             bool
	cancel            context.CancelFunc
	done              chan struct{}
}

func (m *mcpServer) codexHeartbeatSnapshot() *codexFrozenHeartbeat {
	m.sessionMu.RLock()
	defer m.sessionMu.RUnlock()
	if !m.sessionContextSet || m.sessionToken == "" || m.sessionScope == "" || m.sessionGroupID == "" || m.endpointID == "" || m.sessionPublic.BindingID == "" || m.sessionPublic.BindingEpoch == 0 || m.sessionPublic.NetworkCard.PrincipalID == "" {
		return nil
	}
	t := m.sessionContext
	var connection *LocalNodeConnection
	var pin *LocalNodeConnectionPin
	if m.localNode != nil {
		frozen := *m.localNode
		connection, pin = &frozen, &frozen.Pin
	}
	return &codexFrozenHeartbeat{connection: connection, cache: mcpCachedSession{ConnectionPin: pin, Scope: m.sessionScope, APIOrigin: m.baseURL, Harness: t.Harness, NativeSessionID: t.NativeSessionID,
		NodeID: t.NodeID, Workspace: t.Workspace, GroupID: m.sessionGroupID, EndpointID: m.endpointID, OwnerID: m.sessionPublic.Endpoint.Owner,
		BindingID: m.sessionPublic.BindingID, BindingEpoch: m.sessionPublic.BindingEpoch, LeaseExpiresAt: m.sessionPublic.LeaseExpiresAt, SessionToken: m.sessionToken, codexDomainBinding: m.sessionDomain},
		principal: m.sessionPublic.NetworkCard.PrincipalID, socket: m.joinSocketPath(harness.SessionContext{MachineID: t.NodeID}), pqtls: m.pqtlsSelected}
}

func (h *codexFrozenHeartbeat) same(other *codexFrozenHeartbeat) bool {
	if h == nil || other == nil {
		return false
	}
	a, b := h.cache, other.cache
	if (a.ConnectionPin == nil) != (b.ConnectionPin == nil) || a.ConnectionPin != nil && *a.ConnectionPin != *b.ConnectionPin {
		return false
	}
	a.ConnectionPin, b.ConnectionPin = nil, nil
	return a == b && h.principal == other.principal && h.socket == other.socket && h.pqtls == other.pqtls
}

func (h *codexFrozenHeartbeat) matches(m *mcpServer) bool { return h.same(m.codexHeartbeatSnapshot()) }

func (m *mcpServer) stopCodexHeartbeat() {
	if m.codexContext == nil {
		return
	}
	state := m.codexContext
	state.heartbeatMu.Lock()
	defer state.heartbeatMu.Unlock()
	if h := state.heartbeat; h != nil {
		state.heartbeat = nil
		h.cancel()
		<-h.done // Cancellation closes the request; install B only after A exits.
	}
}

func (m *mcpServer) reconcileCodexHeartbeat() {
	state := m.codexContext
	if state == nil {
		return
	}
	state.mu.RLock()
	active := state.active
	state.mu.RUnlock()
	if active == nil {
		return
	}
	candidate := m.codexHeartbeatSnapshot()
	if candidate != nil && (candidate.cache.NativeSessionID != active.NativeSessionID || candidate.cache.Workspace != active.Workspace || candidate.cache.NodeID != active.MachineID || candidate.cache.Harness != active.Harness) {
		candidate = nil
	}
	state.heartbeatMu.Lock()
	defer state.heartbeatMu.Unlock()
	if old := state.heartbeat; old != nil {
		if old.same(candidate) {
			select {
			case <-old.done:
			default:
				return
			}
		}
		state.heartbeat = nil
		old.cancel()
		<-old.done
	}
	if candidate == nil || !candidate.matches(m) {
		return
	}
	ctx, cancel := context.WithCancel(context.Background())
	candidate.cancel, candidate.done = cancel, make(chan struct{})
	state.heartbeat = candidate
	go candidate.run(ctx, m)
}

func (h *codexFrozenHeartbeat) run(ctx context.Context, m *mcpServer) {
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()
	h.runWithTicks(ctx, m, ticker.C)
}

func (h *codexFrozenHeartbeat) runWithTicks(ctx context.Context, m *mcpServer, ticks <-chan time.Time) {
	defer close(h.done)
	for {
		select {
		case <-ctx.Done():
			return
		case <-m.stop:
			return
		case <-ticks:
			if !h.matches(m) {
				return
			}
			_, err := h.renew(ctx)
			if ctx.Err() != nil {
				return
			}
			if errors.Is(err, ErrLocalNodeBindingChanged) || errors.Is(err, ErrLocalNodeConfigRequired) {
				h.clearMemoryIfMatching(m)
				return
			}
			var response *mcpHTTPError
			if errors.As(err, &response) && (response.statusCode == http.StatusUnauthorized || response.statusCode == http.StatusForbidden) {
				h.clearMemoryIfMatching(m)
				return
			}
		}
	}
}

func (h *codexFrozenHeartbeat) clearMemoryIfMatching(m *mcpServer) {
	m.sessionMu.Lock()
	defer m.sessionMu.Unlock()
	if (h.connection == nil) != (m.localNode == nil) || h.connection != nil && h.connection.Pin != m.localNode.Pin {
		return
	}
	t := m.sessionContext
	if m.baseURL != h.cache.APIOrigin || m.sessionToken != h.cache.SessionToken || m.sessionScope != h.cache.Scope || m.sessionGroupID != h.cache.GroupID || m.endpointID != h.cache.EndpointID ||
		m.sessionDomain != h.cache.codexDomainBinding ||
		m.pqtlsSelected != h.pqtls || m.sessionPublic.Endpoint.Owner != h.cache.OwnerID || m.sessionPublic.LeaseExpiresAt != h.cache.LeaseExpiresAt ||
		!m.sessionContextSet || t.Harness != h.cache.Harness || t.NativeSessionID != h.cache.NativeSessionID || t.NodeID != h.cache.NodeID || t.Workspace != h.cache.Workspace ||
		m.sessionPublic.BindingID != h.cache.BindingID || m.sessionPublic.BindingEpoch != h.cache.BindingEpoch || m.sessionPublic.NetworkCard.PrincipalID != h.principal {
		return
	}
	m.sessionToken, m.endpointID, m.sessionGroupID, m.sessionScope = "", "", "", ""
	m.sessionContext, m.sessionContextSet, m.sessionPublic = mcpTrustedContext{}, false, mcpPublicJoinResult{}
	m.sessionDomain = codexDomainBinding{}
}

func (h *codexFrozenHeartbeat) renew(ctx context.Context) (any, error) {
	if err := revalidateCodexLocalNode(ctx, h.connection); err != nil {
		return nil, err
	}
	var raw []byte
	var status int
	if h.pqtls {
		result, err := requestMachineAgentMCPMetadataContext(ctx, h.socket, localMCPMetadataRequest{Operation: "mcp_metadata_heartbeat", Harness: h.cache.Harness,
			NativeSessionID: h.cache.NativeSessionID, NodeID: h.cache.NodeID, Workspace: h.cache.Workspace, APIOrigin: h.cache.APIOrigin,
			SessionToken: h.cache.SessionToken, EndpointID: h.cache.EndpointID, PrincipalID: h.principal, GroupID: h.cache.GroupID, BindingID: h.cache.BindingID, BindingEpoch: h.cache.BindingEpoch})
		if err != nil {
			return nil, err
		}
		raw, status = result.Body, result.StatusCode
	} else {
		request, err := http.NewRequestWithContext(ctx, http.MethodPost, h.cache.APIOrigin+"/v2/fabric/heartbeat", nil)
		if err != nil {
			return nil, err
		}
		request.Header.Set("Authorization", "CicadaSession "+h.cache.SessionToken)
		request.Header.Set("Cicada-Group-Scope", h.cache.GroupID)
		client := &http.Client{Timeout: 30 * time.Second, CheckRedirect: rejectNodeRedirect}
		if h.connection == nil {
			client, err = machineNodeHTTPClient(ctx, 30*time.Second)
			if err != nil {
				return nil, err
			}
		}
		response, err := client.Do(request)
		if err != nil {
			return nil, err
		}
		defer response.Body.Close()
		if h.connection != nil && response.StatusCode >= 300 && response.StatusCode < 400 {
			return nil, errors.New("Cicada Hub redirect refused; heartbeat unconfirmed")
		}
		raw, err = io.ReadAll(io.LimitReader(response.Body, localMCPMetadataMaxBody+1))
		if err != nil || len(raw) > localMCPMetadataMaxBody {
			return nil, errors.New("invalid frozen heartbeat response")
		}
		status = response.StatusCode
	}
	if status >= 400 {
		return nil, &mcpHTTPError{statusCode: status, status: http.StatusText(status)}
	}
	if len(strings.TrimSpace(string(raw))) == 0 {
		return map[string]any{}, nil
	}
	var result any
	if json.Unmarshal(raw, &result) != nil || validateRestoredHeartbeat(result, &h.cache) != nil {
		return nil, errors.New("frozen heartbeat changed its bound actor")
	}
	return result, nil
}
