package main

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"strconv"
	"syscall"
	"time"

	"github.com/cicada-ai/cicada/internal/control"
	"github.com/cicada-ai/cicada/internal/e2ee"
	"github.com/cicada-ai/cicada/internal/fabric"
	"github.com/cicada-ai/cicada/internal/server"
	"github.com/cicada-ai/cicada/internal/store"
)

// This mode reads the existing trust identity, never generates a replacement,
// and constructs no Control instance, planner, job scheduler or reporter.
func serveFabricOnly(host string, port int, config control.Config) error {
	identityPath := config.IdentityFile
	if identityPath == "" {
		identityPath = filepath.Join(config.StateDir, "e2ee", "identity.json")
	}
	data, err := os.ReadFile(identityPath)
	if err != nil {
		return fmt.Errorf("Fabric-only requires an existing trusted identity: %w", err)
	}
	identity, err := e2ee.UnmarshalIdentity(data)
	if err != nil {
		return errors.New("Fabric-only identity is invalid; no replacement was generated")
	}
	persistence, err := store.New(filepath.Join(config.StateDir, "cicada.sqlite3"))
	if err != nil {
		return err
	}
	defer persistence.Close()
	service, err := fabric.NewService(persistence, identity.Public().ID, identity.Public().ID)
	if err != nil {
		return err
	}
	httpServer := &http.Server{Addr: net.JoinHostPort(host, strconv.Itoa(port)), Handler: server.NewFabricHandler(service, config.APIToken), ReadHeaderTimeout: 10 * time.Second}
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	go func() {
		<-ctx.Done()
		shutdown, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		_ = httpServer.Shutdown(shutdown)
	}()
	fmt.Printf("Cicada Fabric listening on %s (Control business disabled)\n", httpServer.Addr)
	err = httpServer.ListenAndServe()
	if errors.Is(err, http.ErrServerClosed) {
		return nil
	}
	return err
}
