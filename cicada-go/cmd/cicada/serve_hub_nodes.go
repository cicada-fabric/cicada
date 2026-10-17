package main

import (
	"context"
	"errors"
	"fmt"
	"os/signal"
	"path/filepath"
	"syscall"

	"github.com/cicada-ai/cicada/internal/clientoperator"
	"github.com/cicada-ai/cicada/internal/control"
	"github.com/cicada-ai/cicada/internal/e2ee"
	"github.com/cicada-ai/cicada/internal/hubauth"
	"github.com/cicada-ai/cicada/internal/hubidentity"
	"github.com/cicada-ai/cicada/internal/hubnodes"
	"github.com/cicada-ai/cicada/internal/hubowner"
	"github.com/cicada-ai/cicada/internal/server"
	"github.com/cicada-ai/cicada/internal/store"
)

// Node composition requires all three retained identities. The existing safe
// private-file reader neither creates missing keys nor repairs/rotates them.
func existingHubNodeIdentities(config control.Config) (hubidentity.Set, error) {
	peer := config.IdentityFile
	if peer == "" {
		peer = filepath.Join(config.StateDir, "e2ee", "identity.json")
	}
	paths := []string{peer, filepath.Join(config.StateDir, "e2ee", "client-control-identity.json"), filepath.Join(config.StateDir, "e2ee", "node-control-identity.json")}
	var ids [3]*e2ee.Identity
	for i, path := range paths {
		raw, err := clientoperator.ReadPrivateFile(path, 32*1024)
		if err != nil {
			return hubidentity.Set{}, errors.New("Hub Nodes mode requires the three existing private Hub identities; no replacement was generated")
		}
		ids[i], err = e2ee.UnmarshalIdentity(raw)
		clear(raw)
		if err != nil {
			return hubidentity.Set{}, errors.New("retained Hub identity is invalid; no replacement was generated")
		}
	}
	return hubidentity.Set{Peer: ids[0], ClientControl: ids[1], NodeControl: ids[2]}, nil
}

func serveHubNodesOnly(host string, port int, config control.Config) error {
	if err := checkHubServeReadiness(config); err != nil {
		return err
	}
	lease, err := store.AcquireStateStartup(config.StateDir)
	if err != nil {
		return err
	}
	ids, err := existingHubNodeIdentities(config)
	if err != nil {
		lease.Close()
		return err
	}
	db, err := store.New(filepath.Join(config.StateDir, "cicada.sqlite3"))
	if err != nil {
		lease.Close()
		return err
	}
	defer db.Close()
	owner, err := hubowner.NewService(db, ids)
	if err != nil {
		lease.Close()
		return err
	}
	auth, err := hubauth.NewServiceWithNodeAuthority(db, ids)
	if err != nil {
		lease.Close()
		return err
	}
	nodes, err := hubnodes.NewService(db, ids)
	lease.Close()
	if err != nil {
		return err
	}
	front := newControlHTTPServer(host, port, server.NewHubNodesHandler(owner, auth, nodes))
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	fmt.Printf("Cicada Hub Nodes listening on %s (finite App Node authority; Control business disabled)\n", front.Addr)
	err = serveProductHTTP(ctx, front, nil, nil)
	if errors.Is(err, context.Canceled) {
		return nil
	}
	return err
}
