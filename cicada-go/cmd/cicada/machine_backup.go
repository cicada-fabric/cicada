package main

import (
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/cicada-ai/cicada/internal/nodebackup"
)

const machineBackupUsage = "usage: cicada machine backup --id ID --state-dir DIR [--writer-root DIR] --output NEW_DIR | verify --backup DIR | restore --backup DIR --state-dir DIR [--writer-root DIR]"

func machineBackupCommand(args []string) error {
	return machineBackupCommandOutput(args, os.Stdout)
}

func machineBackupCommandOutput(args []string, output io.Writer) error {
	if len(args) == 0 {
		return errors.New(machineBackupUsage)
	}
	subcommand := strings.ToLower(strings.TrimSpace(args[0]))
	flags := flag.NewFlagSet("machine "+subcommand, flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	id := flags.String("id", "", "stable Node ID")
	stateDir := flags.String("state-dir", "", "Node StateDir")
	writerRoot := flags.String("writer-root", "", "shared Node WriterRoot (defaults to --state-dir)")
	backupDir := flags.String("backup", "", "Node backup directory")
	outputDir := flags.String("output", "", "new Node backup directory")
	if err := flags.Parse(args[1:]); err != nil {
		return fmt.Errorf("%s: %w", machineBackupUsage, err)
	}
	if len(flags.Args()) != 0 {
		return errors.New(machineBackupUsage)
	}
	switch subcommand {
	case "backup":
		if strings.TrimSpace(*id) == "" || strings.TrimSpace(*stateDir) == "" || strings.TrimSpace(*outputDir) == "" {
			return errors.New("machine backup requires explicit --id, --state-dir, and --output")
		}
		if strings.TrimSpace(*writerRoot) == "" {
			*writerRoot = *stateDir
		}
		report, err := nodebackup.BackupWithWriterRoot(*stateDir, *id, *writerRoot, *outputDir)
		if err != nil {
			return err
		}
		return encodeMachineBackupJSON(output, report)
	case "verify":
		if strings.TrimSpace(*backupDir) == "" {
			return errors.New("machine verify requires explicit --backup")
		}
		manifest, err := nodebackup.Verify(*backupDir)
		if err != nil {
			return err
		}
		return encodeMachineBackupJSON(output, manifest)
	case "restore":
		if strings.TrimSpace(*backupDir) == "" || strings.TrimSpace(*stateDir) == "" {
			return errors.New("machine restore requires explicit --backup and --state-dir")
		}
		if strings.TrimSpace(*writerRoot) == "" {
			*writerRoot = *stateDir
		}
		report, err := nodebackup.RestoreWithWriterRoot(*backupDir, *stateDir, *writerRoot)
		if err != nil {
			return err
		}
		return encodeMachineBackupJSON(output, report)
	default:
		return errors.New(machineBackupUsage)
	}
}

func encodeMachineBackupJSON(output io.Writer, value any) error {
	if output == nil {
		return errors.New("machine backup output is nil")
	}
	encoder := json.NewEncoder(output)
	encoder.SetEscapeHTML(false)
	if err := encoder.Encode(value); err != nil {
		return fmt.Errorf("encode machine backup result: %w", err)
	}
	return nil
}
