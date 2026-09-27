package main

// The migration inventory command is deliberately local and read-only.  It
// opens the selected SQLite database through store.InventoryLegacyMigration,
// which uses a mode=ro URI instead of Store.New.  No API server, network
// connector, credential, or migration writer is involved.

import (
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/cicada-ai/cicada/internal/store"
)

const migrationInventoryUsage = "usage: cicada migration inventory --db PATH [--format json] [--limit N]"

// migrationInventoryCommand is intended to be wired from main.go as:
//
//	case "migration":
//	    if err := migrationInventoryCommand(os.Args[2:]); err != nil { ... }
//
// Keeping dispatch out of this file lets the existing command switch remain
// under the caller's control while making the command independently testable.
func migrationInventoryCommand(args []string) error {
	return migrationInventoryCommandOutput(args, os.Stdout)
}

func migrationInventoryCommandOutput(args []string, output io.Writer) error {
	if len(args) > 0 && (strings.EqualFold(strings.TrimSpace(args[0]), "inventory") || strings.EqualFold(strings.TrimSpace(args[0]), "dry-run")) {
		args = args[1:]
	}
	flags := flag.NewFlagSet("migration inventory", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	database := flags.String("db", strings.TrimSpace(os.Getenv("CICADA_STATE_DB")), "legacy SQLite database to inspect (read-only; required unless CICADA_STATE_DB is set)")
	databaseAlias := flags.String("database", "", "compatibility alias for --db")
	pathAlias := flags.String("path", "", "compatibility alias for --db")
	format := flags.String("format", "json", "report format (json only)")
	dryRun := flags.Bool("dry-run", true, "assert that this command is an inventory-only dry-run")
	limit := flags.Int("limit", 0, "maximum endpoint projections (counts remain complete; 0 means all)")
	if err := flags.Parse(args); err != nil {
		return err
	}
	if len(flags.Args()) != 0 {
		return errors.New(migrationInventoryUsage)
	}
	if strings.TrimSpace(*databaseAlias) != "" {
		*database = strings.TrimSpace(*databaseAlias)
	}
	if strings.TrimSpace(*pathAlias) != "" {
		*database = strings.TrimSpace(*pathAlias)
	}
	if strings.TrimSpace(*database) == "" {
		return store.ErrMigrationInventoryDatabaseRequired
	}
	if !*dryRun {
		return store.ErrMigrationInventoryApplyUnsupported
	}
	if *limit < 0 {
		return errors.New("migration inventory --limit must be non-negative")
	}
	if !strings.EqualFold(strings.TrimSpace(*format), "json") {
		return errors.New("migration inventory supports only --format json")
	}
	inventory, err := store.InventoryLegacyMigrationWithOptions(strings.TrimSpace(*database), store.LegacyMigrationInventoryOptions{EndpointLimit: *limit})
	if err != nil {
		return err
	}
	encoder := json.NewEncoder(output)
	encoder.SetIndent("", "  ")
	if err := encoder.Encode(inventory); err != nil {
		return fmt.Errorf("encode migration inventory: %w", err)
	}
	return nil
}
