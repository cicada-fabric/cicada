package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/cicada-ai/cicada/internal/store"
)

const migrationRestoreActivationUsage = "usage: cicada migration recovery register --source PATH --trust-file PATH --trust-sha256 SHA256 | prepare --source PATH --backup DIR --capsule DIR --state-dir PATH | status|reconcile|activate --source PATH --state-dir PATH"

func migrationRestoreActivationCommand(args []string) error {
	return migrationRestoreActivationCommandOutput(args, os.Stdout)
}

// These are local maintenance operations on the one Store authority. In
// particular, status never opens a writable Store, and an absent authority
// never becomes a bootstrap or an activation permission.
func migrationRestoreActivationCommandOutput(args []string, output io.Writer) error {
	if output == nil {
		return errors.New("migration recovery output is nil")
	}
	if len(args) == 0 {
		return errors.New(migrationRestoreActivationUsage)
	}
	operation := args[0]
	switch operation {
	case "register", "prepare", "status", "reconcile", "activate":
	default:
		return errors.New(migrationRestoreActivationUsage)
	}
	flags := flag.NewFlagSet("migration recovery "+operation, flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	source := flags.String("source", "", "exact previously established original SOURCE StateDir")
	var target, base, capsule, trust, trustSHA *string
	switch operation {
	case "register":
		trust = flags.String("trust-file", "", "preexisting independent established-source pin file")
		trustSHA = flags.String("trust-sha256", "", "independently established exact pin file SHA-256")
	case "prepare":
		target = flags.String("state-dir", "", "exact designated restore target")
		base = flags.String("backup", "", "existing older B backup")
		capsule = flags.String("capsule", "", "new complete current C capsule directory")
	default:
		target = flags.String("state-dir", "", "exact designated restore target")
	}
	if err := flags.Parse(args[1:]); err != nil {
		return fmt.Errorf("%s: %w", migrationRestoreActivationUsage, err)
	}
	if len(flags.Args()) != 0 {
		return errors.New(migrationRestoreActivationUsage)
	}
	required := []struct {
		name  string
		value *string
	}{{"--source", source}}
	if target != nil {
		required = append(required, struct {
			name  string
			value *string
		}{"--state-dir", target})
	}
	if base != nil {
		required = append(required, struct {
			name  string
			value *string
		}{"--backup", base}, struct {
			name  string
			value *string
		}{"--capsule", capsule})
	}
	if trust != nil {
		required = append(required, struct {
			name  string
			value *string
		}{"--trust-file", trust}, struct {
			name  string
			value *string
		}{"--trust-sha256", trustSHA})
	}
	for _, field := range required {
		*field.value = strings.TrimSpace(*field.value)
		if *field.value == "" {
			return fmt.Errorf("migration recovery %s requires explicit %s", operation, field.name)
		}
	}
	var result any
	var err error
	switch operation {
	case "register":
		result, err = store.RegisterEstablishedHubSource(context.Background(), store.HubRestoreRegistrationOptions{SourceStateDir: *source, IndependentTrustFile: *trust, IndependentTrustSHA256: *trustSHA})
	case "prepare":
		result, err = store.PrepareHubRestoreHandover(context.Background(), store.HubRestorePrepareOptions{SourceStateDir: *source, BaseBackupDir: *base, CapsuleDir: *capsule, TargetStateDir: *target})
	case "status":
		result, err = store.InspectHubRestoreHandover(store.HubRestoreOperationOptions{SourceStateDir: *source, TargetStateDir: *target})
	case "reconcile":
		result, err = store.ReconcileHubRestoreHandover(context.Background(), store.HubRestoreOperationOptions{SourceStateDir: *source, TargetStateDir: *target})
	case "activate":
		result, err = store.ActivateHubRestoreHandover(context.Background(), store.HubRestoreOperationOptions{SourceStateDir: *source, TargetStateDir: *target})
	}
	if err != nil {
		return err
	}
	encoder := json.NewEncoder(output)
	encoder.SetEscapeHTML(false)
	if err = encoder.Encode(result); err != nil {
		return fmt.Errorf("encode migration recovery result: %w", err)
	}
	return nil
}
