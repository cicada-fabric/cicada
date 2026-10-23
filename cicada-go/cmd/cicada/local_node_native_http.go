package main

import (
	"context"
	"net/http"
	"sync"
	"time"

	"github.com/cicada-ai/cicada/internal/hubtransport"
)

// One selected MCP/heartbeat pair owns one pool. The immutable authority pin
// remains in its original state; only a freshly revalidated Node may supply an
// updated numeric route for the same descriptor and exact binding.
type localNodeHTTPPool struct {
	mu                  sync.Mutex
	transport           *hubtransport.Transport
	descriptor, address string
}

func (p *localNodeHTTPPool) client(ctx context.Context, connection *LocalNodeConnection, timeout time.Duration) (*http.Client, error) {
	if connection == nil {
		return machineNodeHTTPClient(ctx, timeout)
	}
	old := connection.Pin
	current, err := ResolveLocalNodeConnection(ctx, LocalNodeSelection{UserRoot: old.UserRoot, HubID: old.HubID, NodeID: old.NodeID}, &old)
	if err != nil {
		return nil, codexLocalNodeError(err)
	}
	if current.Pin.HubTransportDescriptor == "" {
		return &http.Client{Timeout: timeout, CheckRedirect: rejectNodeRedirect}, nil
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.transport == nil || p.address != current.Pin.HubDialAddress || p.descriptor != current.Pin.HubTransportDescriptor {
		d, err := hubtransport.DecodeDescriptor(current.Pin.HubTransportDescriptor)
		if err != nil {
			return nil, err
		}
		next, err := hubtransport.NewTransport(d, current.Pin.HubDialAddress)
		if err != nil {
			return nil, err
		}
		if p.transport != nil {
			p.transport.CloseIdleConnections()
		}
		p.transport = next
		p.descriptor = current.Pin.HubTransportDescriptor
		p.address = current.Pin.HubDialAddress
	}
	return &http.Client{Transport: p.transport, Timeout: timeout, CheckRedirect: rejectNodeRedirect}, nil
}

func (p *localNodeHTTPPool) close() {
	if p == nil {
		return
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.transport != nil {
		p.transport.CloseIdleConnections()
	}
}

func (m *mcpServer) selectedNodeHTTPPool() *localNodeHTTPPool {
	m.nativeHTTPOnce.Do(func() { m.nativeHTTP = &localNodeHTTPPool{} })
	return m.nativeHTTP
}
