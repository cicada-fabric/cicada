package main

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"time"

	"github.com/cicada-ai/cicada/internal/control"
	"github.com/cicada-ai/cicada/internal/fabric"
	"github.com/cicada-ai/cicada/internal/nodetransport"
	"github.com/cicada-ai/cicada/internal/pqtls"
	"github.com/cicada-ai/cicada/internal/server"
)

// HTTP handlers and SSE finish before Control shuts down its shared Store.
// This ordering also closes Control when either listener cannot start.
func serveManagedProductHTTP(ctx context.Context, front *http.Server, controlPlane *control.Control, cfg *nodetransport.Config) error {
	serveErr := serveProductHTTP(ctx, front, controlPlane.Fabric(), cfg)
	shutdown, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	return errors.Join(serveErr, controlPlane.Shutdown(shutdown))
}

func loadHubPQTransport(path string) (*nodetransport.Config, error) {
	if path == "" {
		return nil, nil
	}
	if err := pqtls.Available(); err != nil {
		return nil, err
	}
	return nodetransport.Load(path, "hub")
}

// serveProductHTTP serves both boundaries in one process with one authority.
// Both listeners are acquired before either starts accepting HTTP requests.
func serveProductHTTP(ctx context.Context, front *http.Server, service *fabric.Service, cfg *nodetransport.Config) error {
	listeners := []net.Listener{}
	servers := []*http.Server{front}
	if cfg != nil {
		if err := cfg.Validate("hub"); err != nil {
			return err
		}
		listener, err := pqtls.Listen("tcp", cfg.Listen, cfg.TLSConfig())
		if err != nil {
			return err
		}
		listeners = append(listeners, listener)
		defer listener.Close()
		nodeServer := newControlHTTPServer("", 0, server.WithNodePQTransport(front.Handler, service, cfg, true))
		nodeServer.Addr = cfg.Listen
		nodeServer.ConnContext = pqtls.HTTPConnContext
		servers = append(servers, nodeServer)
		front.Handler = server.WithNodePQTransport(front.Handler, service, cfg, false)
		fmt.Printf("Cicada enrolled Node PQ TLS listening on %s\n", listener.Addr())
	}
	frontListener, err := net.Listen("tcp", front.Addr)
	if err != nil {
		return err
	}
	defer frontListener.Close()
	if cfg != nil {
		listeners = append([]net.Listener{frontListener}, listeners...)
	} else {
		listeners = append(listeners, frontListener)
	}
	results := make(chan error, len(servers))
	for i, s := range servers {
		s.BaseContext = func(net.Listener) context.Context { return ctx }
		go func(s *http.Server, l net.Listener) { results <- s.Serve(l) }(s, listeners[i])
	}
	var serveErr error
	remaining := len(servers)
	select {
	case <-ctx.Done():
	case serveErr = <-results:
		remaining--
	}
	shutdown, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	// Cancel closes SSE request contexts through Close, after graceful requests
	// have had their bounded opportunity to finish. Join every Serve goroutine.
	for _, s := range servers {
		_ = s.Shutdown(shutdown)
		_ = s.Close()
	}
	for i := 0; i < remaining; i++ {
		<-results
	}
	if errors.Is(serveErr, http.ErrServerClosed) {
		return nil
	}
	return serveErr
}
