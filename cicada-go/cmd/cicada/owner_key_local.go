package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/cicada-ai/cicada/internal/e2ee"
	"github.com/cicada-ai/cicada/internal/store"
)

const ownerKeyLocalUsage = "usage: cicada owner-key generate --private FILE --public FILE | register --db HUB_DB --owner-id OWNER --public FILE --expect-key-id KEY_ID | revoke --db HUB_DB --owner-id OWNER --key-id KEY_ID --expected-version N"

// ownerKeyLocalCommand is deliberately a direct, local database operation.
// It has no HTTP equivalent and accepts only a public key on registration.
// The operator must independently verify --expect-key-id with the user who
// holds the private key. Management/Node/Fabric credentials cannot call it.
func ownerKeyLocalCommand(args []string, output io.Writer) error {
	if len(args) == 0 || output == nil {
		return errors.New(ownerKeyLocalUsage)
	}
	subcommand := strings.ToLower(strings.TrimSpace(args[0]))
	if subcommand != "generate" && subcommand != "register" && subcommand != "revoke" {
		return errors.New(ownerKeyLocalUsage)
	}
	flags := flag.NewFlagSet("owner-key "+subcommand, flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	dbPath := flags.String("db", "", "existing local Hub SQLite database")
	ownerID := flags.String("owner-id", "", "owner identity bound to the public key")
	publicPath := flags.String("public", "", "user-held identity's public JSON file")
	privatePath := flags.String("private", "", "private owner identity file, created only on the user's trusted machine")
	expectKeyID := flags.String("expect-key-id", "", "public key ID independently verified with the owner")
	keyID := flags.String("key-id", "", "public key ID to revoke")
	expectedVersion := flags.Int64("expected-version", 0, "current key version to revoke")
	if err := flags.Parse(args[1:]); err != nil || len(flags.Args()) != 0 {
		return errors.New(ownerKeyLocalUsage)
	}
	if subcommand == "generate" {
		if *privatePath == "" || *publicPath == "" || *dbPath != "" || *ownerID != "" ||
			*expectKeyID != "" || *keyID != "" || *expectedVersion != 0 {
			return errors.New(ownerKeyLocalUsage)
		}
		return generateOwnerKeyFiles(*privatePath, *publicPath, output)
	}
	if strings.TrimSpace(*dbPath) == "" || strings.TrimSpace(*ownerID) == "" || *privatePath != "" {
		return errors.New(ownerKeyLocalUsage)
	}
	info, err := os.Lstat(*dbPath)
	if err != nil {
		return fmt.Errorf("inspect existing Hub database: %w", err)
	}
	if !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 {
		return errors.New("Hub database must be an existing regular file, not a symlink")
	}
	var public e2ee.PublicIdentity
	if subcommand == "register" {
		if *publicPath == "" || *expectKeyID == "" || *keyID != "" || *expectedVersion != 0 {
			return errors.New(ownerKeyLocalUsage)
		}
		publicFile, err := os.Open(*publicPath)
		if err != nil {
			return err
		}
		defer publicFile.Close()
		data, err := io.ReadAll(io.LimitReader(publicFile, 32769))
		if err != nil {
			return err
		}
		if len(data) == 0 || len(data) > 32768 {
			return errors.New("owner public identity file has invalid size")
		}
		decoder := json.NewDecoder(bytes.NewReader(data))
		decoder.DisallowUnknownFields()
		if err := decoder.Decode(&public); err != nil {
			return fmt.Errorf("decode owner public identity: %w", err)
		}
		var trailing any
		if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
			return errors.New("owner public identity has trailing data")
		}
		if err := e2ee.ValidatePublicIdentity(public); err != nil {
			return err
		}
		if public.ID != *expectKeyID {
			return errors.New("owner key ID differs from independently verified ID")
		}
	} else if *keyID == "" || *expectedVersion <= 0 || *publicPath != "" || *expectKeyID != "" {
		return errors.New(ownerKeyLocalUsage)
	}
	persistence, err := store.New(*dbPath)
	if err != nil {
		return err
	}
	defer persistence.Close()
	var key *store.OwnerApprovalKey
	if subcommand == "register" {
		key, err = persistence.RegisterOwnerApprovalKeyLocal(*ownerID, public)
	} else {
		key, err = persistence.RevokeOwnerApprovalKeyLocal(*ownerID, *keyID, *expectedVersion)
	}
	if err != nil {
		return err
	}
	return json.NewEncoder(output).Encode(struct {
		OwnerID string `json:"owner_id"`
		KeyID   string `json:"key_id"`
		State   string `json:"state"`
		Version int64  `json:"version"`
	}{key.OwnerID, key.KeyID, key.State, key.Version})
}

// generateOwnerKeyFiles is an offline development/bootstrap aid. The private
// key stays on the user's trusted machine and must never be copied to the Hub
// that runs Control or Relay. Existing files are never overwritten.
func generateOwnerKeyFiles(privatePath, publicPath string, output io.Writer) error {
	privateAbs, err := filepath.Abs(privatePath)
	if err != nil {
		return err
	}
	publicAbs, err := filepath.Abs(publicPath)
	if err != nil {
		return err
	}
	if privateAbs == publicAbs {
		return errors.New("owner private and public paths must differ")
	}
	privateParent, err := os.Lstat(filepath.Dir(privateAbs))
	if err != nil {
		return fmt.Errorf("inspect private key directory: %w", err)
	}
	if !privateParent.IsDir() || privateParent.Mode().Perm() != 0o700 {
		return errors.New("owner private key directory must already exist with mode 0700")
	}
	if _, err := os.Lstat(privateAbs); err == nil {
		return errors.New("owner private key file already exists")
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	if _, err := os.Lstat(publicAbs); err == nil {
		return errors.New("owner public key file already exists")
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	identity, err := e2ee.NewIdentity()
	if err != nil {
		return err
	}
	private, err := identity.MarshalBinary()
	if err != nil {
		return err
	}
	public, err := json.Marshal(identity.Public())
	if err != nil {
		return err
	}
	privateFile, err := os.OpenFile(privateAbs, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return fmt.Errorf("create owner private key without overwrite: %w", err)
	}
	if _, err := privateFile.Write(private); err != nil {
		privateFile.Close()
		return err
	}
	if err := privateFile.Sync(); err != nil {
		privateFile.Close()
		return err
	}
	if err := privateFile.Close(); err != nil {
		return err
	}
	publicFile, err := os.OpenFile(publicAbs, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o644)
	if err != nil {
		return fmt.Errorf("create owner public key without overwrite (private key remains at requested path): %w", err)
	}
	if _, err := publicFile.Write(append(public, '\n')); err != nil {
		publicFile.Close()
		return err
	}
	if err := publicFile.Sync(); err != nil {
		publicFile.Close()
		return err
	}
	if err := publicFile.Close(); err != nil {
		return err
	}
	return json.NewEncoder(output).Encode(struct {
		KeyID       string `json:"key_id"`
		PublicPath  string `json:"public_path"`
		PrivatePath string `json:"private_path"`
	}{identity.Public().ID, publicAbs, privateAbs})
}
