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
	"github.com/cloudflare/circl/kem/mlkem/mlkem768"
	"github.com/cloudflare/circl/sign/mldsa/mldsa65"
	"github.com/mattn/go-isatty"
)

const ownerSignerUsage = "usage: cicada owner-signer prepare|prepare-openssl|bootstrap|recover|grant --profile DIR [options]"

type ownerSignerProfile interface {
	Close() error
	PublicManifest() ownersigner.PublicManifest
	ExportManifest(string) (string, error)
	Bootstrap(context.Context, []byte, func(ownersigner.BootstrapReview) error) (*ownerbootstrap.Receipt, error)
	Recover(context.Context, func(ownersigner.BootstrapReview) error) (*ownerbootstrap.Receipt, error)
	SignDeviceGrant([]byte, time.Time, func(ownersigner.GrantReview) error) ([]byte, error)
}

type ownerSignerGrantSummary struct {
	Format            string              `json:"format"`
	State             string              `json:"state"`
	HubID             string              `json:"hub_id"`
	OwnerID           string              `json:"owner_id"`
	OwnerKeyID        string              `json:"owner_key_id"`
	OwnerPublic       e2ee.PublicIdentity `json:"owner_public_identity"`
	DeviceID          string              `json:"device_id"`
	DeviceKeyID       string              `json:"device_key_id"`
	DeviceFingerprint string              `json:"device_key_fingerprint"`
	Purpose           string              `json:"purpose"`
	IssuedAt          string              `json:"issued_at"`
	ExpiresAt         string              `json:"expires_at"`
	GrantFile         string              `json:"grant_file"`
}

func writeOwnerSignerGrantSummary(output io.Writer, summaryPath string, summary ownerSignerGrantSummary) error {
	if output == nil {
		return errors.New("grant summary output is unavailable")
	}
	if summary.Format != "cicada.owner-device-grant-summary.v1" || summary.State != "GRANT_WRITTEN" ||
		!safeReviewID(summary.HubID) || !safeReviewID(summary.OwnerID) || !safeReviewID(summary.OwnerKeyID) ||
		!safeReviewID(summary.DeviceID) || !safeReviewID(summary.DeviceKeyID) || !validFingerprint(summary.DeviceFingerprint) ||
		!safeTerminalText(summary.GrantFile) || !safeCanonicalTimestamp(summary.IssuedAt) || !safeCanonicalTimestamp(summary.ExpiresAt) ||
		summary.Purpose != e2ee.OwnerDevicePurposeControl || e2ee.ValidatePublicIdentity(summary.OwnerPublic) != nil ||
		summary.OwnerPublic.ID != summary.OwnerKeyID {
		return errors.New("public Owner grant summary is invalid")
	}
	data, err := json.Marshal(summary)
	if err != nil {
		return errors.New("public grant summary could not be encoded")
	}
	if summaryPath != "" {
		if err := ownersigner.WriteGrantSummaryExclusive(summaryPath, append(data, '\n')); err != nil {
			return err
		}
	}
	return json.NewEncoder(output).Encode(summary)
}

func openOwnerSignerProfile(dir string) (ownerSignerProfile, error) {
	external, err := ownersigner.OpenExternal(dir)
	if err == nil {
		return external, nil
	}
	if !errors.Is(err, ownersigner.ErrNotExternalProfile) {
		return nil, err
	}
	return ownersigner.Open(dir)
}

func ownerSignerCommand(args []string, input io.Reader, output io.Writer) error {
	if len(args) == 0 || output == nil {
		return errors.New(ownerSignerUsage)
	}
	command := args[0]
	flags := flag.NewFlagSet("owner-signer "+command, flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	profileDir := flags.String("profile", "", "Owner-only profile directory (Unix 0700; Windows current-user and SYSTEM ACL)")
	connectionPath := flags.String("connection-file", "", "independently supplied public Hub Owner connection file")
	importPath := flags.String("import-private", "", "optional existing mode 0600 Owner identity to use as the first candidate")
	pairPath := flags.String("pair-file", "", "locally issued public Owner bootstrap pairing file")
	manifestPath := flags.String("manifest-file", "", "public Client device enrollment manifest")
	grantPath := flags.String("output", "", "new protected Owner-signed grant file (Unix 0600; Windows current-user and SYSTEM ACL)")
	grantSummaryPath := flags.String("summary-output", "", "optional exclusive public JSON grant summary file")
	expiresRaw := flags.String("expires-at", "", "Owner grant expiry in canonical UTC RFC3339Nano format")
	opensslPath := flags.String("openssl", "", "absolute OpenSSL 3.5+ executable path")
	kemPrivatePath := flags.String("kem-private", "", "existing encrypted ML-KEM-768 private PEM path")
	signingPrivatePath := flags.String("signing-private", "", "existing encrypted ML-DSA-65 private PEM path")
	kemPublicPath := flags.String("kem-public", "", "existing ML-KEM-768 SPKI public PEM path")
	signingPublicPath := flags.String("signing-public", "", "existing ML-DSA-65 SPKI public PEM path")
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

	case "prepare-openssl":
		if *connectionPath == "" || *opensslPath == "" || *kemPrivatePath == "" || *signingPrivatePath == "" || *kemPublicPath == "" || *signingPublicPath == "" {
			return errors.New("owner-signer prepare-openssl requires --connection-file, --openssl, --kem-private, --signing-private, --kem-public, and --signing-public")
		}
		var connection ownersigner.ConnectionFile
		if err := readStrictPublicJSON(*connectionPath, 64*1024, &connection); err != nil {
			return errors.New("public Hub Owner connection file is invalid")
		}
		if err := connection.Validate(); err != nil {
			return err
		}
		kemPEM, err := readPublicFile(*kemPublicPath, 16*1024)
		if err != nil {
			return errors.New("ML-KEM public SPKI file is unavailable")
		}
		kem, err := parseOwnerOpenSSLPublic(kemPEM, ownerMLKEM768OID, mlkem768.PublicKeySize)
		if err != nil {
			return fmt.Errorf("ML-KEM public SPKI: %w", err)
		}
		signingPEM, err := readPublicFile(*signingPublicPath, 16*1024)
		if err != nil {
			return errors.New("ML-DSA public SPKI file is unavailable")
		}
		signing, err := parseOwnerOpenSSLPublic(signingPEM, ownerMLDSA65OID, mldsa65.PublicKeySize)
		if err != nil {
			return fmt.Errorf("ML-DSA public SPKI: %w", err)
		}
		ownerPublic, err := e2ee.NewPublicIdentity(kem, signing)
		if err != nil {
			return errors.New("existing OpenSSL public keys do not form a valid Cicada Owner identity")
		}
		fingerprint := ownerbootstrap.Fingerprint(ownerPublic)
		if err := ownerSignerPrepareOpenSSLReview(input, output, connection, ownerPublic, fingerprint); err != nil {
			return err
		}
		profile, err := ownersigner.PrepareExternal(*profileDir, connection, ownerPublic, ownersigner.OpenSSLPaths{
			Executable: *opensslPath, KEMPrivate: *kemPrivatePath, SigningPrivate: *signingPrivatePath,
		})
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
		pairBytes, err := readPublicFile(*pairPath, 256*1024)
		if err != nil {
			return errors.New("Owner bootstrap pairing file must be a bounded regular file without symlinks")
		}
		profile, err := openOwnerSignerProfile(*profileDir)
		if err != nil {
			return err
		}
		defer profile.Close()
		receipt, err := profile.Bootstrap(context.Background(), pairBytes, ownerSignerBootstrapReview(input, output))
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
		profile, err := openOwnerSignerProfile(*profileDir)
		if err != nil {
			return err
		}
		defer profile.Close()
		receipt, err := profile.Recover(context.Background(), ownerSignerBootstrapReview(input, output))
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
		profile, err := openOwnerSignerProfile(*profileDir)
		if err != nil {
			return err
		}
		defer profile.Close()
		grant, err := profile.SignDeviceGrant(manifestBytes, expires, ownerSignerGrantReview(input, output))
		if err != nil {
			return err
		}
		if err := ownersigner.WriteGrantFileExclusive(*grantPath, grant); err != nil {
			return err
		}
		var manifest clientoperator.EnrollmentManifest
		if err := decodeStrictBridgeJSON(manifestBytes, &manifest); err != nil {
			return errors.New("Client enrollment manifest is invalid")
		}
		ownerManifest := profile.PublicManifest()
		var signedGrant e2ee.OwnerDeviceGrant
		if err := decodeStrictBridgeJSON(grant, &signedGrant); err != nil {
			return errors.New("signed Owner device grant is invalid")
		}
		fingerprint, _ := e2ee.OwnerDevicePublicKeyFingerprint(manifest.DevicePublicIdentity)
		summary := ownerSignerGrantSummary{"cicada.owner-device-grant-summary.v1", "GRANT_WRITTEN", manifest.HubID, manifest.OwnerID,
			ownerManifest.OwnerPublic.ID, ownerManifest.OwnerPublic, manifest.DeviceID,
			manifest.DevicePublicIdentity.ID, fingerprint, manifest.Purpose, signedGrant.IssuedAt, signedGrant.ExpiresAt, *grantPath}
		return writeOwnerSignerGrantSummary(output, *grantSummaryPath, summary)
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

func ownerSignerPrepareOpenSSLReview(input io.Reader, output io.Writer, connection ownersigner.ConnectionFile, owner e2ee.PublicIdentity, fingerprint string) error {
	if !safeReviewID(connection.AccountID) || !safeReviewID(connection.OwnerID) || !safeReviewID(connection.Hub.HubID) ||
		!safeTerminalText(connection.Origin) || !safeReviewID(owner.ID) || !validFingerprint(fingerprint) ||
		fingerprint != ownerbootstrap.Fingerprint(owner) {
		return errors.New("external Owner preparation contains unsafe or invalid public fields")
	}
	if err := requireOwnerSignerTTY(input, output); err != nil {
		return err
	}
	fmt.Fprintf(output, "Review the existing OpenSSL public Owner candidate before creating its local profile:\nAccount: %s\nOwner: %s\nHub: %s\nOrigin: %s\nOwner key ID: %s\nFull Owner public fingerprint: %s\nPrivate PEM files remain encrypted and are opened only by OpenSSL. Type `approve %s` to save these public pins and key paths: ",
		connection.AccountID, connection.OwnerID, connection.Hub.HubID, connection.Origin, owner.ID, fingerprint, fingerprint)
	return requireExactTerminalLine(input, "approve "+fingerprint)
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
