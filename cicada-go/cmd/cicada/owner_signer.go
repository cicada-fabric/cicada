package main

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"strings"
	"time"

	"github.com/cicada-ai/cicada/internal/clientoperator"
	"github.com/cicada-ai/cicada/internal/e2ee"
	"github.com/cicada-ai/cicada/internal/ownerbootstrap"
	"github.com/cicada-ai/cicada/internal/ownersigner"
	"github.com/mattn/go-isatty"
)

const ownerSignerUsage = "usage: cicada owner-signer prepare|bootstrap|recover|grant --profile DIR [options]"

func ownerSignerCommand(args []string, input io.Reader, output io.Writer) error {
	if len(args) == 0 || output == nil {
		return errors.New(ownerSignerUsage)
	}
	command := args[0]
	flags := flag.NewFlagSet("owner-signer "+command, flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	profileDir := flags.String("profile", "", "Owner-only private profile directory (mode 0700)")
	connectionPath := flags.String("connection-file", "", "independently supplied public Hub Owner connection file")
	importPath := flags.String("import-private", "", "optional existing mode 0600 Owner identity to use as the first candidate")
	pairPath := flags.String("pair-file", "", "locally issued mode 0600 Owner bootstrap pairing file")
	manifestPath := flags.String("manifest-file", "", "public Client device enrollment manifest")
	grantPath := flags.String("output", "", "new mode 0600 Owner-signed grant file")
	expiresRaw := flags.String("expires-at", "", "Owner grant expiry in canonical UTC RFC3339Nano format")
	if err := flags.Parse(args[1:]); err != nil || len(flags.Args()) != 0 || *profileDir == "" {
		return errors.New(ownerSignerUsage)
	}

	switch command {
	case "prepare":
		if *connectionPath == "" {
			return errors.New("owner-signer prepare requires --connection-file from the Hub operator")
		}
		var connection ownersigner.ConnectionFile
		if err := readStrictPublicJSON(*connectionPath, 64*1024, &connection); err != nil {
			return errors.New("public Hub Owner connection file is invalid")
		}
		if err := connection.Validate(); err != nil {
			return err
		}
		var identity *e2ee.Identity
		if *importPath != "" {
			data, err := clientoperator.ReadPrivateFile(*importPath, 32*1024)
			if err != nil {
				return errors.New("imported Owner identity must be a regular mode 0600 file without symlinks")
			}
			identity, err = e2ee.UnmarshalIdentity(data)
			if err != nil || e2ee.ValidatePublicIdentity(identity.Public()) != nil {
				return errors.New("imported Owner identity is invalid")
			}
		}
		profile, err := ownersigner.Prepare(*profileDir, connection.AccountID, connection.OwnerID,
			connection.Origin, connection.Hub, connection.AllowLoopbackHTTP, identity)
		if err != nil {
			return err
		}
		defer profile.Close()
		publicPath, err := profile.ExportManifest("")
		if err != nil {
			return err
		}
		manifest := profile.PublicManifest()
		return json.NewEncoder(output).Encode(struct {
			State         string `json:"state"`
			AccountID     string `json:"account_id"`
			OwnerID       string `json:"owner_id"`
			OwnerKeyID    string `json:"owner_key_id"`
			Fingerprint   string `json:"fingerprint"`
			PublicFile    string `json:"public_manifest_file"`
			PrivateFolder string `json:"private_profile_dir"`
		}{"NEEDS_BOOTSTRAP", manifest.AccountID, manifest.OwnerID, manifest.OwnerPublic.ID, manifest.Fingerprint, publicPath, *profileDir})

	case "bootstrap":
		if *pairPath == "" {
			return errors.New("owner-signer bootstrap requires --pair-file")
		}
		pairBytes, err := clientoperator.ReadPrivateFile(*pairPath, 256*1024)
		if err != nil {
			return errors.New("Owner bootstrap pairing file must be a regular mode 0600 file without symlinks")
		}
		profile, err := ownersigner.Open(*profileDir)
		if err != nil {
			return err
		}
		defer profile.Close()
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		receipt, err := profile.Bootstrap(ctx, pairBytes, ownerSignerBootstrapReview(input, output))
		if err != nil {
			return err
		}
		return json.NewEncoder(output).Encode(struct {
			State       string `json:"state"`
			AccountID   string `json:"account_id"`
			OwnerID     string `json:"owner_id"`
			KeyID       string `json:"owner_key_id"`
			AuthorityID string `json:"authority_id"`
			Version     int64  `json:"version"`
		}{receipt.State, receipt.AccountID, receipt.OwnerID, receipt.KeyID, receipt.AuthorityID, receipt.Version})

	case "recover":
		profile, err := ownersigner.Open(*profileDir)
		if err != nil {
			return err
		}
		defer profile.Close()
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		receipt, err := profile.Recover(ctx, ownerSignerBootstrapReview(input, output))
		if err != nil {
			return err
		}
		return json.NewEncoder(output).Encode(struct {
			State       string `json:"state"`
			AccountID   string `json:"account_id"`
			OwnerID     string `json:"owner_id"`
			KeyID       string `json:"owner_key_id"`
			AuthorityID string `json:"authority_id"`
			Version     int64  `json:"version"`
		}{receipt.State, receipt.AccountID, receipt.OwnerID, receipt.KeyID, receipt.AuthorityID, receipt.Version})

	case "grant":
		if *manifestPath == "" || *grantPath == "" || *expiresRaw == "" {
			return errors.New("owner-signer grant requires --manifest-file, --expires-at, and --output")
		}
		manifestBytes, err := readPublicFile(*manifestPath, 64*1024)
		if err != nil {
			return errors.New("Client enrollment manifest is unavailable")
		}
		expires, err := time.Parse(time.RFC3339Nano, strings.TrimSpace(*expiresRaw))
		if err != nil || expires.UTC().Format(time.RFC3339Nano) != strings.TrimSpace(*expiresRaw) {
			return errors.New("grant expiry must be canonical UTC RFC3339Nano")
		}
		profile, err := ownersigner.Open(*profileDir)
		if err != nil {
			return err
		}
		defer profile.Close()
		grant, err := profile.SignDeviceGrant(manifestBytes, expires, ownerSignerGrantReview(input, output))
		if err != nil {
			return err
		}
		if err := writePrivateExclusive(*grantPath, grant); err != nil {
			return err
		}
		var manifest clientoperator.EnrollmentManifest
		if err := decodeStrictBridgeJSON(manifestBytes, &manifest); err != nil {
			return errors.New("Client enrollment manifest is invalid")
		}
		fingerprint, _ := e2ee.OwnerDevicePublicKeyFingerprint(manifest.DevicePublicIdentity)
		return json.NewEncoder(output).Encode(struct {
			State             string `json:"state"`
			HubID             string `json:"hub_id"`
			OwnerID           string `json:"owner_id"`
			DeviceID          string `json:"device_id"`
			DeviceKeyID       string `json:"device_key_id"`
			DeviceFingerprint string `json:"device_key_fingerprint"`
			Purpose           string `json:"purpose"`
			ExpiresAt         string `json:"expires_at"`
			GrantFile         string `json:"grant_file"`
		}{"GRANT_WRITTEN", manifest.HubID, manifest.OwnerID, manifest.DeviceID,
			manifest.DevicePublicIdentity.ID, fingerprint, manifest.Purpose, expires.Format(time.RFC3339Nano), *grantPath})
	default:
		return errors.New(ownerSignerUsage)
	}
}

func ownerSignerBootstrapReview(input io.Reader, output io.Writer) func(ownersigner.BootstrapReview) error {
	return func(r ownersigner.BootstrapReview) error {
		if !safeReviewID(r.AccountID) || !safeReviewID(r.OwnerID) || !safeReviewID(r.HubID) ||
			!safeTerminalText(r.Origin) || r.Purpose != ownerbootstrap.Purpose ||
			!safeReviewID(r.AuthorityID) || !safeReviewID(r.OperationID) || !validFingerprint(r.Fingerprint) ||
			!safeCanonicalTimestamp(r.ExpiresAt) {
			return errors.New("Owner bootstrap review contains unsafe or invalid public fields")
		}
		if err := requireOwnerSignerTTY(input, output); err != nil {
			return err
		}
		fmt.Fprintf(output, "Review the independently supplied Owner bootstrap pairing:\nAccount: %s\nOwner: %s\nHub: %s\nOrigin: %s\nPurpose: %s\nAuthority: %s\nOperation: %s\nCandidate full public fingerprint: %s\nExpires: %s\nCompare every value with the Hub operator's public setup record. Type `approve %s` to create/reuse the exact first-Owner proof: ",
			r.AccountID, r.OwnerID, r.HubID, r.Origin, r.Purpose, r.AuthorityID, r.OperationID, r.Fingerprint, r.ExpiresAt, r.Fingerprint)
		return requireExactTerminalLine(input, "approve "+r.Fingerprint)
	}
}

func ownerSignerGrantReview(input io.Reader, output io.Writer) func(ownersigner.GrantReview) error {
	return func(r ownersigner.GrantReview) error {
		if !safeReviewID(r.AccountID) || !safeReviewID(r.OwnerID) || !safeReviewID(r.OwnerKeyID) ||
			!safeReviewID(r.HubID) || !safeReviewID(r.DeviceID) || !safeReviewID(r.DeviceKeyID) ||
			!validFingerprint(r.DeviceFingerprint) || r.Purpose != e2ee.OwnerDevicePurposeControl ||
			!safeCanonicalTimestamp(r.IssuedAt) || !safeCanonicalTimestamp(r.ExpiresAt) {
			return errors.New("Owner device grant review contains unsafe or invalid public fields")
		}
		if err := requireOwnerSignerTTY(input, output); err != nil {
			return err
		}
		fmt.Fprintf(output, "Review the exact Client device grant scope:\nAccount: %s\nOwner: %s\nOwner signing key: %s\nHub: %s\nDevice: %s\nDevice key: %s\nDevice full public fingerprint: %s\nPurpose: %s\nIssued: %s\nExpires: %s\nThe Hub must still report this signing key ACTIVE at enrollment time. Type `approve %s` to sign: ",
			r.AccountID, r.OwnerID, r.OwnerKeyID, r.HubID, r.DeviceID, r.DeviceKeyID, r.DeviceFingerprint, r.Purpose, r.IssuedAt, r.ExpiresAt, r.DeviceFingerprint)
		return requireExactTerminalLine(input, "approve "+r.DeviceFingerprint)
	}
}

func safeCanonicalTimestamp(value string) bool {
	if !safeTerminalText(value) {
		return false
	}
	parsed, err := time.Parse(time.RFC3339Nano, value)
	return err == nil && parsed.UTC().Format(time.RFC3339Nano) == value
}

func requireOwnerSignerTTY(input io.Reader, output io.Writer) error {
	in, ok := input.(*os.File)
	if !ok || !isatty.IsTerminal(in.Fd()) {
		return errors.New("Owner signer review requires an interactive terminal")
	}
	out, ok := output.(*os.File)
	if !ok || !isatty.IsTerminal(out.Fd()) {
		return errors.New("Owner signer review details must be visible on an interactive terminal")
	}
	return nil
}

func requireExactTerminalLine(input io.Reader, expected string) error {
	line, err := bufio.NewReader(io.LimitReader(input, 512)).ReadString('\n')
	if err != nil || strings.TrimSpace(line) != expected {
		return errors.New("Owner signer operation was not confirmed with the exact reviewed fingerprint")
	}
	return nil
}
