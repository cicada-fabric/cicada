package main

import (
	"context"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/cicada-ai/cicada/internal/nodetransport"
	"github.com/cicada-ai/cicada/internal/store"
)

func configureMachinePQTransport(hub *machineHubContext, path string) error {
	if path == "" {
		return nil
	}
	if hub == nil || hub.TLSRuntime != nil || hub.NodeTransport != nil {
		return nodetransport.ErrTLSInstall
	}
	runtime, err := nodetransport.OpenRuntime(context.Background(), nodetransport.RuntimeOptions{StateRoot: hub.StateDir, WriterRoot: hub.WriterRoot, HubID: hub.HubID, NodeID: hub.NodeID, ApplicationOrigin: hub.Origin, ConfigPath: path, OpenLocal: func() (*nodetransport.LocalTLSInstaller, func(), error) { return machineTLSOpenLocal(hub) }, QueryCurrent: func(ctx context.Context, cfg *nodetransport.Config) (*store.NodeTLSAuthoritySnapshot, error) {
		return machineTLSQueryCurrent(ctx, hub, cfg)
	}})
	if err != nil {
		return err
	}
	hub.TLSRuntime = runtime
	hub.NodeTransport = runtime
	return nil
}

// machineNodeHTTPClient is shared by Node Relay, Session and encrypted Control
// requests. Its per-Hub transport never consults a global replacement transport.
func machineNodeHTTPClient(ctx context.Context, timeout time.Duration) (*http.Client, error) {
	client := &http.Client{Timeout: timeout, CheckRedirect: rejectNodeRedirect}
	if hub, ok := machineHubFrom(ctx); ok {
		if hub.NodeTransport == nil && strings.TrimSpace(os.Getenv("CICADA_NODE_PQTLS_CONFIG")) != "" {
			return nil, nodetransport.ErrTLSCurrentAuthorityUnavailable
		}
		client.Transport = hub.NodeTransport
		return client, nil
	}
	if path := strings.TrimSpace(os.Getenv("CICADA_NODE_PQTLS_CONFIG")); path != "" {
		return nil, nodetransport.ErrTLSCurrentAuthorityUnavailable
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
