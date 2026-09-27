package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/cicada-ai/cicada/internal/e2ee"
	"github.com/cicada-ai/cicada/internal/nodekeys"
	"github.com/cicada-ai/cicada/internal/nodelock"
)

const machineOwnerKeyTrustUsage = "usage: cicada machine trust-owner-key --id NODE_ID --state-dir DIR --owner-id OWNER --public FILE --expect-key-id KEY_ID --expect-fingerprint SHA256 | revoke-owner-key --id NODE_ID --state-dir DIR --owner-id OWNER --key-id KEY_ID --expected-version N"

// machineOwnerKeyTrustCommand changes only this Node's private trust store.
// A public key and both expected identifiers must arrive through independent
// owner verification; the Hub authorization Bundle is never a trust root.
func machineOwnerKeyTrustCommand(operation string, args []string, output io.Writer) error {
	if output == nil || operation != "trust-owner-key" && operation != "revoke-owner-key" {
		return errors.New(machineOwnerKeyTrustUsage)
	}
	flags := flag.NewFlagSet("machine "+operation, flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	nodeID := flags.String("id", envOr("CICADA_MACHINE_ID", ""), "stable Node ID")
	stateDir := flags.String("state-dir", machineAgentStateDir(), "Node-local state directory")
	ownerID := flags.String("owner-id", "", "independently verified Owner ID")
	publicPath := flags.String("public", "", "Owner public identity JSON")
	expectKeyID := flags.String("expect-key-id", "", "independently verified key ID")
	expectFingerprint := flags.String("expect-fingerprint", "", "independently verified SHA-256 fingerprint")
	keyID := flags.String("key-id", "", "trusted Owner key ID to revoke")
	expectedVersion := flags.Int64("expected-version", 0, "current local trust version")
	if err := flags.Parse(args); err != nil || len(flags.Args()) != 0 ||
		strings.TrimSpace(*nodeID) == "" || strings.TrimSpace(*stateDir) == "" ||
		strings.TrimSpace(*ownerID) == "" {
		return errors.New(machineOwnerKeyTrustUsage)
	}
	*nodeID = strings.TrimSpace(*nodeID)
	*stateDir = strings.TrimSpace(*stateDir)
	if operation == "trust-owner-key" {
		if *publicPath == "" || *expectKeyID == "" || *expectFingerprint == "" ||
			*keyID != "" || *expectedVersion != 0 {
			return errors.New(machineOwnerKeyTrustUsage)
		}
	} else if *keyID == "" || *expectedVersion <= 0 || *publicPath != "" ||
		*expectKeyID != "" || *expectFingerprint != "" {
		return errors.New(machineOwnerKeyTrustUsage)
	}
	maintenance, err := nodelock.AcquireMaintenance(*stateDir, *nodeID)
	if err != nil {
		return fmt.Errorf("lock Node owner-key trust state: %w", err)
	}
	defer maintenance.Close()
	state, err := nodekeys.OpenCryptoState(machineNodeStateDir(*stateDir, *nodeID))
	if err != nil {
		return err
	}
	defer state.Close()
	var trust *nodekeys.OwnerKeyTrust
	if operation == "trust-owner-key" {
		var public e2ee.PublicIdentity
		public, err = readMachineOwnerPublicIdentity(*publicPath)
		if err != nil {
			return err
		}
		if public.ID != *expectKeyID {
			return errors.New("Owner public key ID differs from independently verified ID")
		}
		trust, err = state.TrustOwnerApprovalKeyLocal(*ownerID, *expectKeyID,
			public, *expectFingerprint)
	} else {
		trust, err = state.RevokeNodeOwnerKeyTrustLocal(*ownerID, *keyID, *expectedVersion)
	}
	if err != nil {
		return err
	}
	return json.NewEncoder(output).Encode(struct {
		OwnerID     string `json:"owner_id"`
		KeyID       string `json:"key_id"`
		Fingerprint string `json:"fingerprint"`
		State       string `json:"state"`
		Version     int64  `json:"version"`
	}{trust.OwnerID, trust.KeyID, trust.ExpectedFingerprint, trust.State, trust.Version})
}

func readMachineOwnerPublicIdentity(path string) (e2ee.PublicIdentity, error) {
	info, err := os.Lstat(path)
	if err != nil {
		return e2ee.PublicIdentity{}, fmt.Errorf("inspect Owner public key file: %w", err)
	}
	if !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 {
		return e2ee.PublicIdentity{}, errors.New("Owner public key must be an existing regular file")
	}
	file, err := os.Open(path)
	if err != nil {
		return e2ee.PublicIdentity{}, err
	}
	defer file.Close()
	data, err := io.ReadAll(io.LimitReader(file, 32769))
	if err != nil {
		return e2ee.PublicIdentity{}, err
	}
	if len(data) == 0 || len(data) > 32768 {
		return e2ee.PublicIdentity{}, errors.New("Owner public key file has invalid size")
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	var public e2ee.PublicIdentity
	if err := decoder.Decode(&public); err != nil {
		return e2ee.PublicIdentity{}, fmt.Errorf("decode Owner public key: %w", err)
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		return e2ee.PublicIdentity{}, errors.New("Owner public key has trailing data")
	}
	if err := e2ee.ValidatePublicIdentity(public); err != nil {
		return e2ee.PublicIdentity{}, err
	}
	return public, nil
}
