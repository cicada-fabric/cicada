package main

import (
	"context"
	"encoding/json"
	"flag"
	"io"
	"os/signal"
	"strings"
	"syscall"
)

func nodeHubsCommand(args []string, out io.Writer) error {
	if len(args) == 0 {
		return ErrLocalNodeHubConfig
	}
	action := args[0]
	args = args[1:]
	if action != "list" && action != "add" && action != "remove" {
		return ErrLocalNodeHubConfig
	}
	selector := ""
	if len(args) > 0 && !strings.HasPrefix(args[0], "-") {
		selector = args[0]
		args = args[1:]
	}
	seen := map[string]bool{}
	for i := 0; i < len(args); i++ {
		if !strings.HasPrefix(args[i], "--") {
			return ErrLocalNodeHubConfig
		}
		key, _, inline := strings.Cut(strings.TrimPrefix(args[i], "--"), "=")
		if seen[key] {
			return ErrLocalNodeHubConfig
		}
		seen[key] = true
		if !inline && key != "from-service" && key != "retry-pairing" {
			i++
			if i >= len(args) {
				return ErrLocalNodeHubConfig
			}
		}
	}
	f := flag.NewFlagSet("node hubs "+action, flag.ContinueOnError)
	f.SetOutput(io.Discard)
	root := f.String("user-root", "", "")
	alias := f.String("alias", "", "")
	name := f.String("node-name", "", "")
	adopt := f.Bool("from-service", false, "")
	retry := f.Bool("retry-pairing", false, "")
	if f.Parse(args) != nil || len(f.Args()) != 0 {
		return ErrLocalNodeHubConfig
	}
	ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer cancel()
	switch action {
	case "list":
		if selector != "" || len(seen) > 0 && (seen["alias"] || seen["node-name"] || seen["from-service"] || seen["retry-pairing"]) {
			return ErrLocalNodeHubConfig
		}
		v, err := ListLocalNodeHubConnections(ctx, *root)
		if err != nil {
			return err
		}
		return json.NewEncoder(out).Encode(v)
	case "remove":
		if selector == "" || seen["alias"] || seen["node-name"] || seen["from-service"] || seen["retry-pairing"] {
			return ErrLocalNodeHubConfig
		}
		s, err := nodeHubHumanSelection(ctx, *root, selector)
		if err != nil && err != errNodeHubNotFound {
			return err
		}
		v, err := RemoveLocalNodeHubConnection(ctx, s)
		if err != nil {
			return err
		}
		return json.NewEncoder(out).Encode(v)
	case "add":
		in := LocalNodeHubAddInput{UserRoot: *root, Alias: *alias, NodeName: *name, FromService: *adopt, RetryPairing: *retry}
		if *adopt {
			if selector != "" || *retry || *name != "" {
				return ErrLocalNodeHubConfig
			}
		} else {
			if selector == "" {
				return ErrLocalNodeHubConfig
			}
			s, err := nodeHubHumanSelection(ctx, *root, selector)
			if err != nil && err != errNodeHubNotFound {
				return err
			}
			if s.ConnectionID != "" {
				in.ConnectionID = s.ConnectionID
			} else if s.HubAddress != "" {
				in.HubAddress = s.HubAddress
				if in.Alias == "" {
					return ErrLocalNodeHubConfig
				}
			} else {
				if in.Alias != "" && !strings.EqualFold(in.Alias, s.Alias) {
					return errNodeHubConflict
				}
				in.Alias = s.Alias
			}
		}
		v, err := AddLocalNodeHubConnection(ctx, in)
		if err != nil {
			return err
		}
		return json.NewEncoder(out).Encode(v)
	}
	return ErrLocalNodeHubConfig
}

func nodeHubHumanSelection(ctx context.Context, userRoot, selector string) (LocalNodeHubSelection, error) {
	root, _, err := nodeHubRoot(ctx, userRoot, false)
	if err != nil {
		return LocalNodeHubSelection{}, err
	}
	defer root.Close()
	r, _, err := readNodeHubRegistry(root)
	if err != nil {
		return LocalNodeHubSelection{}, err
	}
	var matches []nodeHubRegistryEntry
	for _, e := range r.Connections {
		if strings.EqualFold(e.Alias, selector) || e.HubAddress == selector {
			matches = append(matches, e)
		}
	}
	if len(matches) > 1 {
		return LocalNodeHubSelection{}, errNodeHubConflict
	}
	if len(matches) == 1 {
		return LocalNodeHubSelection{UserRoot: userRoot, ConnectionID: matches[0].ConnectionID}, nil
	}
	s := nodeHubEntryAddressSelection(userRoot, selector)
	return s, errNodeHubNotFound
}
