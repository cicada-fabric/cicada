package main

// The migration backup command is intentionally separate from the existing
// read-only inventory command.  The main dispatcher may route the "backup",
// "verify", and "restore" subcommands here without making inventory mutate a
// StateDir by accident.

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

const migrationBackupUsage = "usage: cicada migration backup --state-dir PATH --output DIR | verify --backup DIR | restore --backup DIR --state-dir PATH"

func migrationBackupCommand(args []string) error {
	return migrationBackupCommandOutput(args, os.Stdout)
}

// migrationBackupCommandOutput is kept small and side-effect explicit so the
// command can be tested without replacing os.Stdout.  The source/target paths
// are required flags; no default StateDir is selected for backup or restore.
func migrationBackupCommandOutput(args []string, output io.Writer) error {
	if len(args) == 0 {
		return errors.New(migrationBackupUsage)
	}
	subcommand := strings.ToLower(strings.TrimSpace(args[0]))
	flags := flag.NewFlagSet("migration "+subcommand, flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	stateDir := flags.String("state-dir", "", "source or target StateDir")
	backupDir := flags.String("backup", "", "backup directory")
	backupAlias := flags.String("backup-dir", "", "compatibility alias for --backup")
	outputDir := flags.String("output", "", "new backup directory")
	outputAlias := flags.String("destination", "", "compatibility alias for --output")
	if err := flags.Parse(args[1:]); err != nil {
		return fmt.Errorf("%s: %w", migrationBackupUsage, err)
	}
	if len(flags.Args()) != 0 {
		return errors.New(migrationBackupUsage)
	}
	if strings.TrimSpace(*backupDir) == "" {
		*backupDir = strings.TrimSpace(*backupAlias)
	}
	if strings.TrimSpace(*outputDir) == "" {
		*outputDir = strings.TrimSpace(*outputAlias)
	}
	switch subcommand {
	case "backup":
		if strings.TrimSpace(*stateDir) == "" || strings.TrimSpace(*outputDir) == "" {
			return errors.New("migration backup requires explicit --state-dir and --output")
		}
		manifest, err := store.BackupStateDir(strings.TrimSpace(*stateDir), strings.TrimSpace(*outputDir))
		if err != nil {
			return err
		}
		return encodeMigrationBackupJSON(output, manifest)
	case "verify", "validate":
		if strings.TrimSpace(*backupDir) == "" {
			return errors.New("migration verify requires explicit --backup")
		}
		manifest, err := store.VerifyStateBackup(strings.TrimSpace(*backupDir))
		if err != nil {
			return err
		}
		return encodeMigrationBackupJSON(output, manifest)
	case "restore":
		if strings.TrimSpace(*backupDir) == "" || strings.TrimSpace(*stateDir) == "" {
			return errors.New("migration restore requires explicit --backup and --state-dir")
		}
		report, err := store.RestoreStateDir(strings.TrimSpace(*backupDir), strings.TrimSpace(*stateDir))
		if err != nil {
			return err
		}
		return encodeMigrationBackupJSON(output, report)
	default:
		return errors.New(migrationBackupUsage)
	}
}

func encodeMigrationBackupJSON(output io.Writer, value any) error {
	if output == nil {
		return errors.New("migration backup output is nil")
	}
	encoder := json.NewEncoder(output)
	encoder.SetEscapeHTML(false)
	if err := encoder.Encode(value); err != nil {
		return fmt.Errorf("encode migration backup result: %w", err)
	}
	return nil
}
