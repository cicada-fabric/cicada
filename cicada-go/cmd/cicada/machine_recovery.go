package main

import (
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/cicada-ai/cicada/internal/nodebackup"
)

const machineRecoveryUsage = "usage: cicada machine recovery inspect --backup DIR --state-dir DIR"

func machineRecoveryCommand(args []string) error {
	return machineRecoveryCommandOutput(args, os.Stdout)
}

func machineRecoveryCommandOutput(args []string, output io.Writer) error {
	if len(args) == 0 || strings.ToLower(strings.TrimSpace(args[0])) != "recovery" || len(args) < 2 ||
		strings.ToLower(strings.TrimSpace(args[1])) != "inspect" {
		return errors.New(machineRecoveryUsage)
	}
	flags := flag.NewFlagSet("machine recovery inspect", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	backupDir := flags.String("backup", "", "verified Node backup directory")
	stateDir := flags.String("state-dir", "", "restored Node StateDir")
	if err := flags.Parse(args[2:]); err != nil {
		return fmt.Errorf("%s: %w", machineRecoveryUsage, err)
	}
	if len(flags.Args()) != 0 || strings.TrimSpace(*backupDir) == "" || strings.TrimSpace(*stateDir) == "" {
		return errors.New(machineRecoveryUsage)
	}
	report, err := nodebackup.Inspect(*backupDir, *stateDir)
	if err != nil {
		return err
	}
	return encodeMachineBackupJSON(output, report)
}
