package main

import (
	"context"
	"errors"
	"fmt"
	"os/signal"
	"path/filepath"
	"syscall"

	"github.com/cicada-ai/cicada/internal/control"
	"github.com/cicada-ai/cicada/internal/hubauth"
	"github.com/cicada-ai/cicada/internal/hubidentity"
	"github.com/cicada-ai/cicada/internal/hubowner"
	"github.com/cicada-ai/cicada/internal/server"
	"github.com/cicada-ai/cicada/internal/store"
)

// Composition uses Control's existing configuration defaults only; no business
// constructor, Workspace, Machine, model or Fabric session is instantiated.
func openHubAccountServices(config control.Config) (*store.Store, *hubowner.Service, *hubauth.Service, error) {
	lease, e := store.AcquireStateStartup(config.StateDir)
	if e != nil {
		return nil, nil, nil, e
	}
	defer lease.Close()
	db, e := store.New(filepath.Join(config.StateDir, "cicada.sqlite3"))
	if e != nil {
		return nil, nil, nil, e
	}
	ids, e := hubidentity.LoadOrCreate(config.StateDir, config.IdentityFile)
	if e != nil {
		db.Close()
		return nil, nil, nil, e
	}
	owner, e := hubowner.NewService(db, ids)
	if e != nil {
		db.Close()
		return nil, nil, nil, e
	}
	auth, e := hubauth.NewService(db, ids)
	if e != nil {
		db.Close()
		return nil, nil, nil, e
	}
	return db, owner, auth, nil
}
func serveHubOnly(host string, port int, config control.Config) error {
	// A configured account must already have been reserved through local setup.
	// Fail before key creation on wrong/pristine StateDir.
	if e := checkHubServeReadiness(config); e != nil {
		return e
	}
	db, owner, auth, e := openHubAccountServices(config)
	if e != nil {
		return e
	}
	defer db.Close()
	if _, _, e = db.HubAccountSetup(); e != nil {
		return e
	}
	front := newControlHTTPServer(host, port, server.NewHubHandlerWithAccount(owner, auth))
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	fmt.Printf("Cicada Hub listening on %s (Control business disabled)\n", front.Addr)
	e = serveProductHTTP(ctx, front, nil, nil)
	if errors.Is(e, context.Canceled) {
		return nil
	}
	return e
}
