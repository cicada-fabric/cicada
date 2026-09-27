package main

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"strings"
	"time"

	"github.com/cicada-ai/cicada/internal/store"
)

const networkOperatorUsage = "usage: cicada network create|list|migration-dry-run|map-prepare|map-quarantine|map-approve|activate|invite|invite-revoke|member-revoke --db HUB_DB [options]"

// These commands require direct access to an existing Hub state file. They
// are operator maintenance actions, not NetworkAdmin actions. A Network
// access credential, Agent prompt, or global HTTP management bearer cannot
// use this path or create an Owner's signed Join approval.
func networkOperatorCommand(operation string, args []string, output io.Writer) error {
	flags := flag.NewFlagSet("network "+operation, flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	dbPath := flags.String("db", "", "existing local Hub database")
	networkID := flags.String("network", "", "Network ID")
	hubID := flags.String("hub", "", "authoritative Hub ID")
	name := flags.String("name", "", "Network display name")
	ownerID := flags.String("owner", "", "Network Owner ID")
	groupID := flags.String("group", "", "existing Group ID")
	reason := flags.String("reason", "", "mapping review reason")
	expectedVersion := flags.Int64("expected-version", 0, "current Group or membership version")
	targetOwner := flags.String("target-owner", "", "invited Owner ID")
	invitationPath := flags.String("invitation-file", "", "private invitation token file")
	grantsArg := flags.String("grants", "", "exact comma-separated grants")
	ttl := flags.Duration("ttl", 15*time.Minute, "invitation lifetime")
	principalID := flags.String("principal", "", "Network member Principal ID")
	if err := flags.Parse(args); err != nil || len(flags.Args()) != 0 || *dbPath == "" {
		return errors.New(networkOperatorUsage)
	}
	info, err := os.Lstat(*dbPath)
	if err != nil {
		return err
	}
	if !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 {
		return errors.New("Hub database must be an existing regular file")
	}
	// Store.New may run schema migrations. A dry-run must inspect the existing
	// database through a read-only connection before any Store is opened.
	if operation == "migration-dry-run" {
		report, err := store.InspectNetworkMigrationReadOnly(*dbPath)
		if err != nil {
			return err
		}
		return json.NewEncoder(output).Encode(report)
	}
	persistence, err := store.New(*dbPath)
	if err != nil {
		return err
	}
	defer persistence.Close()
	switch operation {
	case "create":
		if *hubID == "" || *name == "" || *ownerID == "" || (*networkID != "" && !validNetworkRouteID(*networkID)) {
			return errors.New("network create requires --hub, --name and --owner")
		}
		created, err := persistence.CreateNetwork(store.Network{ID: *networkID, HubID: *hubID,
			Name: *name, OwnerID: *ownerID})
		if err != nil {
			return err
		}
		return json.NewEncoder(output).Encode(created)
	case "list":
		networks, err := persistence.ListNetworks()
		if err != nil {
			return err
		}
		phase, err := persistence.NetworkMode()
		if err != nil {
			return err
		}
		return json.NewEncoder(output).Encode(map[string]any{"phase": phase, "networks": networks})
	case "map-prepare":
		if *groupID == "" || *networkID == "" || *expectedVersion <= 0 || *reason == "" {
			return errors.New("map-prepare requires Group, Network, current version and review reason")
		}
		mapping, err := persistence.PrepareGroupNetworkMapping(*groupID, *networkID, *reason, *expectedVersion)
		if err != nil {
			return err
		}
		return json.NewEncoder(output).Encode(mapping)
	case "map-approve":
		if *groupID == "" || *networkID == "" || *expectedVersion <= 0 {
			return errors.New("map-approve requires Group, Network and current version")
		}
		if err := persistence.ApproveGroupNetworkMapping(*groupID, *networkID, *expectedVersion); err != nil {
			return err
		}
		return json.NewEncoder(output).Encode(map[string]any{"status": "approved", "group_id": *groupID, "network_id": *networkID})
	case "map-quarantine":
		if *groupID == "" || *expectedVersion <= 0 || *reason == "" {
			return errors.New("map-quarantine requires Group, current version and review reason")
		}
		if err := persistence.QuarantineGroupNetwork(*groupID, *reason, *expectedVersion); err != nil {
			return err
		}
		return json.NewEncoder(output).Encode(map[string]any{"status": "PENDING", "group_id": *groupID})
	case "activate":
		if err := persistence.ActivateNetworkMode(); err != nil {
			return err
		}
		return json.NewEncoder(output).Encode(map[string]any{"phase": "ACTIVE"})
	case "invite":
		if *networkID == "" || *targetOwner == "" || *invitationPath == "" || *ttl <= 0 || *ttl > 23*time.Hour {
			return errors.New("network invite requires Network, target Owner, private file and TTL <= 23 hours")
		}
		network, err := persistence.GetNetwork(*networkID)
		if err != nil {
			return err
		}
		grants := []string{}
		if *grantsArg != "" {
			for _, grant := range strings.Split(*grantsArg, ",") {
				grant = strings.TrimSpace(grant)
				if grant == "" {
					return errors.New("grant set contains an empty value")
				}
				grants = append(grants, grant)
			}
		}
		secret := make([]byte, 32)
		if _, err := rand.Read(secret); err != nil {
			return err
		}
		token := hex.EncodeToString(secret)
		if err := writeNewPrivateNetworkFile(*invitationPath, []byte(token+"\n")); err != nil {
			return err
		}
		expiresAt := time.Now().UTC().Add(*ttl).Format(time.RFC3339Nano)
		if err := persistence.IssueNetworkInvitation(*networkID, *targetOwner, network.OwnerID,
			token, expiresAt, grants); err != nil {
			_ = os.Remove(*invitationPath)
			return err
		}
		return json.NewEncoder(output).Encode(map[string]any{"status": "issued", "network_id": *networkID,
			"target_owner_id": *targetOwner, "invitation_file": *invitationPath,
			"grants": grants, "expires_at": expiresAt})
	case "invite-revoke":
		if *invitationPath == "" {
			return errors.New("invite-revoke requires --invitation-file")
		}
		secret, err := readPrivateNetworkFile(*invitationPath, 16*1024)
		if err != nil {
			return err
		}
		if err := persistence.RevokeNetworkInvitation(string(strings.TrimSpace(string(secret)))); err != nil {
			return err
		}
		return json.NewEncoder(output).Encode(map[string]any{"status": "revoked"})
	case "member-revoke":
		if *networkID == "" || *principalID == "" || *expectedVersion <= 0 {
			return errors.New("member-revoke requires Network, Principal and current revision")
		}
		if err := persistence.RevokeNetworkMembership(*networkID, *principalID, *expectedVersion); err != nil {
			return err
		}
		return json.NewEncoder(output).Encode(map[string]any{"status": "revoked", "network_id": *networkID, "principal_id": *principalID})
	default:
		return fmt.Errorf("unknown Network operator command %q", operation)
	}
}
