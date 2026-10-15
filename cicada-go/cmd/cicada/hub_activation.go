package main

import (
	"encoding/json"
	"errors"
	"flag"
	"io"
	"os"
	"path/filepath"

	wire "github.com/cicada-ai/cicada/internal/hubaccountwire"
	"github.com/cicada-ai/cicada/internal/hubauth"
	"github.com/cicada-ai/cicada/internal/hubidentity"
	"github.com/cicada-ai/cicada/internal/store"
)

func hubActivationIssueCommand(args []string, output io.Writer) error {
	flags := flag.NewFlagSet("hub activation-issue", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	state := flags.String("state-dir", "", "configured Hub StateDir")
	purpose := flags.String("purpose", "", "initial or legacy-pending")
	path := flags.String("code-file", "", "new protected one-use activation code file")
	keyID := flags.String("owner-key-id", "", "exact existing pending Owner key ID for legacy continuation")
	fp := flags.String("owner-fingerprint", "", "full existing pending Owner public fingerprint")
	cancel := flags.Bool("cancel-pending", false, "explicitly cancel pending installation authority before issue")
	if err := flags.Parse(args); err != nil || len(flags.Args()) != 0 || *path == "" || output == nil {
		return errors.New("usage: cicada hub activation-issue --purpose initial|legacy-pending --code-file NEW_0600_FILE [--state-dir DIR] [--owner-key-id ID --owner-fingerprint FULL_SHA256] [--cancel-pending]")
	}
	var authorityPurpose string
	switch *purpose {
	case "initial":
		authorityPurpose = wire.PurposeInitialActivation
		if *keyID != "" || *fp != "" {
			return store.ErrHubAccountRejected
		}
	case "legacy-pending":
		authorityPurpose = wire.PurposeLegacyContinuation
		if !safeReviewID(*keyID) || !validFingerprint(*fp) {
			return store.ErrHubAccountRejected
		}
	default:
		return errors.New("activation purpose must be initial or legacy-pending")
	}
	abs, err := preflightPrivateOutput(*path, "activation code")
	if err != nil {
		return err
	}
	config := hubControlConfig(*state, "")
	startup, err := store.AcquireStateStartup(config.StateDir)
	if err != nil {
		return err
	}
	defer startup.Close()
	db, err := store.New(filepath.Join(config.StateDir, "cicada.sqlite3"))
	if err != nil {
		return err
	}
	defer db.Close()
	if _, _, _, err = db.HubActivationIssueScopeLocal(authorityPurpose, *keyID, *fp); err != nil {
		return err
	}
	// A configured issuer must never repair missing transport keys by rekeying.
	for _, path := range []string{filepath.Join(config.StateDir, "e2ee", "identity.json"), filepath.Join(config.StateDir, "e2ee", "client-control-identity.json"), filepath.Join(config.StateDir, "e2ee", "node-control-identity.json")} {
		info, e := os.Lstat(path)
		if e != nil || !info.Mode().IsRegular() {
			return errors.New("configured Hub identity is missing; activation cannot regenerate keys")
		}
	}
	ids, err := hubidentity.LoadOrCreate(config.StateDir, config.IdentityFile)
	if err != nil {
		return err
	}
	service, err := hubauth.NewService(db, ids)
	if err != nil {
		return err
	}
	m, err := service.IssueActivationLocal(authorityPurpose, *keyID, *fp, *cancel)
	if err != nil {
		return err
	}
	code, err := wire.EncodeActivationCode(*m)
	if err != nil {
		return err
	}
	raw := []byte(code + "\n")
	defer clear(raw)
	if err = writePrivateExclusive(abs, raw); err != nil {
		return errors.New("activation code could not be persisted; explicitly cancel pending authority before retrying")
	}
	return json.NewEncoder(output).Encode(map[string]string{"state": "OWNER_ACTIVATION_ISSUED", "purpose": authorityPurpose, "origin": m.Origin, "code_file": abs, "expires_at": m.ExpiresAt})
}
