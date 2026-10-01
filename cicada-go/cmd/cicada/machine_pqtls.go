package main

import (
	"context"
	"errors"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/cicada-ai/cicada/internal/nodetransport"
)

func configureMachinePQTransport(hub *machineHubContext, path string) error {
	if path == "" {
		return nil
	}
	cfg, err := nodetransport.Load(path, "node")
	if err != nil {
		return err
	}
	if cfg.LogicalOrigin() != hub.Origin || cfg.Identity.HubID != hub.HubID || cfg.Identity.NodeID != hub.NodeID {
		return errors.New("Node PQ transport does not match pinned Hub/Node coordinates")
	}
	transport, err := nodetransport.NewTransport(cfg)
	if err != nil {
		return err
	}
	hub.NodeTransport = transport
	return nil
}

// machineNodeHTTPClient is shared by Node Relay, Session and encrypted Control
// requests. Its per-Hub transport never consults a global replacement transport.
func machineNodeHTTPClient(ctx context.Context, timeout time.Duration) (*http.Client, error) {
	client := &http.Client{Timeout: timeout, CheckRedirect: rejectNodeRedirect}
	if hub, ok := machineHubFrom(ctx); ok {
		client.Transport = hub.NodeTransport
		return client, nil
	}
	if path := strings.TrimSpace(os.Getenv("CICADA_NODE_PQTLS_CONFIG")); path != "" {
		cfg, err := nodetransport.Load(path, "node")
		if err != nil {
			return nil, err
		}
		transport, err := nodetransport.NewTransport(cfg)
		if err != nil {
			return nil, err
		}
		client.Transport = machineOneShotTransport{transport}
	}
	return client, nil
}

// Independent commands have no Agent lifetime in which to close a shared pool.
// Close their connection after each response; Agents retain per-Hub keepalive.
type machineOneShotTransport struct{ base http.RoundTripper }

func (t machineOneShotTransport) RoundTrip(r *http.Request) (*http.Response, error) {
	r = r.Clone(r.Context())
	r.Close = true
	return t.base.RoundTrip(r)
}
