package main

import (
	"bufio"
	"bytes"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"unicode"
	"unicode/utf8"

	"github.com/cicada-ai/cicada/internal/clientoperator"
	"github.com/cicada-ai/cicada/internal/control"
	"github.com/cicada-ai/cicada/internal/e2ee"
	wire "github.com/cicada-ai/cicada/internal/hubaccountwire"
	"github.com/cicada-ai/cicada/internal/hubauth"
	"github.com/cicada-ai/cicada/internal/hubidentity"
	"github.com/cicada-ai/cicada/internal/hubowner"
	"github.com/cicada-ai/cicada/internal/hubtransport"
	"github.com/cicada-ai/cicada/internal/ownerbootstrap"
	"github.com/cicada-ai/cicada/internal/ownersigner"
	"github.com/cicada-ai/cicada/internal/store"
	"github.com/mattn/go-isatty"
)

const hubSetupUsage = "usage: cicada hub setup --owner-label NAME --public-config FILE [--origin HTTPS_ORIGIN] [--native-tls] [--allow-loopback-http] [--adopt-legacy --expect-owner-id ID]"
const hubIssueUsage = "usage: cicada hub owner-bootstrap-issue --candidate-manifest FILE --candidate-fingerprint FULL_SHA256 --pair-file NEW_0600_FILE"

func hubCommand(args []string) error {
	if len(args) == 0 {
		return errors.New("usage: cicada hub setup|account-claim-issue|owner-bootstrap-issue [options]")
	}
	switch args[0] {
	case "native-tls-init":
		return hubNativeTLSCommand(args[1:], os.Stdout, true)
	case "connection-export":
		return hubNativeTLSCommand(args[1:], os.Stdout, false)
	case "activation-issue":
		return hubActivationIssueCommand(args[1:], os.Stdout)
	case "setup":
		return hubSetupCommand(args[1:], os.Stdout)
	case "account-claim-issue":
		return hubAccountClaimIssueCommand(args[1:], os.Stdin, os.Stdout)
	case "owner-bootstrap-issue":
		return hubOwnerBootstrapIssueCommand(args[1:], os.Stdin, os.Stdout)
	default:
		return errors.New("usage: cicada hub setup|account-claim-issue|owner-bootstrap-issue [options]")
	}
}

func hubSetupCommand(args []string, output io.Writer) error {
	if output == nil {
		return errors.New(hubSetupUsage)
	}
	flags := flag.NewFlagSet("hub setup", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	ownerLabel := flags.String("owner-label", "", "label for the stable Hub Owner principal")
	origin := flags.String("origin", "", "exact advertised Hub HTTPS origin")
	nativeTLS := flags.Bool("native-tls", false, "initialize native TLS with the exact logical origin")
	publicConfigPath := flags.String("public-config", "", "new public Hub Owner connection file for the Owner machine")
	allowLoopbackHTTP := flags.Bool("allow-loopback-http", false, "explicit development use of literal loopback HTTP")
	adoptLegacy := flags.Bool("adopt-legacy", false, "adopt an exact existing legacy manager association")
	expectOwnerID := flags.String("expect-owner-id", "", "exact existing legacy Owner ID to retain during adoption")
	stateDir := flags.String("state-dir", "", "Hub StateDir (defaults to CICADA_STATE_DIR or /state)")
	workspaceRoot := flags.String("workspace-root", "", "Hub workspace root (defaults to CICADA_WORKSPACE_ROOT or /workspace)")
	if err := flags.Parse(args); err != nil || len(flags.Args()) != 0 || *ownerLabel == "" || *publicConfigPath == "" {
		return errors.New(hubSetupUsage)
	}
	if !safeTerminalText(*ownerLabel) || strings.TrimSpace(*ownerLabel) == "" || strings.TrimSpace(*ownerLabel) != *ownerLabel {
		return errors.New("Owner label must be visible text without terminal controls or surrounding whitespace")
	}
	if *adoptLegacy != (*expectOwnerID != "") {
		return errors.New("legacy adoption requires both --adopt-legacy and --expect-owner-id")
	}
	if *adoptLegacy && *origin == "" {
		return errors.New("legacy adoption requires its explicit original origin")
	}
	if *nativeTLS && *origin != "" {
		canonical, e := ownerbootstrap.CanonicalOrigin(*origin, false)
		if e != nil || canonical != *origin {
			return errors.New("native TLS requires an exact HTTPS logical origin")
		}
	}
	config := hubControlConfig(*stateDir, *workspaceRoot)
	startup, err := store.AcquireStateStartup(config.StateDir)
	if err != nil {
		return fmt.Errorf("Hub StateDir is unavailable for setup: %w", err)
	}
	defer startup.Close()
	state, err := store.New(filepath.Join(config.StateDir, "cicada.sqlite3"))
	if err != nil {
		return fmt.Errorf("open Hub StateDir: %w", err)
	}
	defer state.Close()
	previous, err := state.GetHubOwnerSetup()
	if err != nil {
		return err
	}
	if *origin == "" {
		if previous != nil {
			*origin = previous.Origin
		} else {
			hubID, e := state.GetClientHubID()
			if e != nil {
				return e
			}
			*origin, err = hubtransport.DefaultOrigin(hubID)
			if err != nil {
				return err
			}
			*nativeTLS = true
		}
	}
	if *nativeTLS {
		canonical, e := ownerbootstrap.CanonicalOrigin(*origin, false)
		if e != nil || canonical != *origin {
			return errors.New("native TLS requires an exact HTTPS logical origin")
		}
	}
	var setup *store.HubOwnerSetup
	if *adoptLegacy {
		setup, err = state.AdoptLegacyHubOwnerLocal(*expectOwnerID, *ownerLabel, *origin, *allowLoopbackHTTP)
	} else {
		setup, err = state.InitializeHubOwnerLocal(*ownerLabel, *origin, *allowLoopbackHTTP)
	}
	if err != nil {
		return fmt.Errorf("initialize local Hub Owner setup: %w", err)
	}

	var identities hubidentity.Set
	if previous != nil || *adoptLegacy {
		identities, err = existingHubNodeIdentities(config)
	} else {
		identities, err = hubidentity.LoadOrCreate(config.StateDir, config.IdentityFile)
	}
	if err != nil {
		return fmt.Errorf("load Hub-owned identities after saving Owner setup: %w", err)
	}
	hubOwner, err := hubowner.NewService(state, identities)
	if err != nil {
		return err
	}
	setup, err = hubOwner.HubOwnerSetup()
	if err != nil || setup == nil || setup.OwnerID == "" {
		return errors.New("Hub Owner setup did not remain bound to the stable local manager")
	}
	hubID, err := hubOwner.ClientHubID()
	if err != nil {
		return err
	}
	connection := ownersigner.ConnectionFile{
		Format: ownersigner.ConnectionFileFormat, Version: 1, Purpose: ownersigner.ConnectionFilePurpose,
		AccountID: setup.AccountID, OwnerID: setup.OwnerID, Origin: setup.Origin,
		AllowLoopbackHTTP: setup.AllowLoopbackHTTP,
		Hub: clientoperator.HubIdentity{Contract: "android-hub-v1", HubID: hubID,
			Public: hubOwner.ClientControlPublicIdentity(), KeyVersion: 1, Suite: clientoperator.Suite},
	}
	if connection.Hub.HubID != setup.HubID || connection.Validate() != nil {
		return errors.New("Hub Client-Control identity does not match the saved Hub Owner setup")
	}
	if *nativeTLS {
		if _, err = initializeHubNativeTLS(config, state, setup, identities); err != nil {
			return err
		}
	}
	if err := state.Close(); err != nil {
		return err
	}
	encoded, err := json.MarshalIndent(connection, "", "  ")
	if err != nil {
		return err
	}
	encoded = append(encoded, '\n')
	if err := writePublicExclusiveOrSame(*publicConfigPath, encoded); err != nil {
		return err
	}
	return json.NewEncoder(output).Encode(struct {
		State      string                     `json:"state"`
		Setup      *store.HubOwnerSetup       `json:"hub_owner_setup"`
		Connection ownersigner.ConnectionFile `json:"public_connection"`
		ConfigFile string                     `json:"public_config_file"`
	}{setup.State, setup, connection, *publicConfigPath})
}

func hubOwnerBootstrapIssueCommand(args []string, input io.Reader, output io.Writer) error {
	if output == nil {
		return errors.New(hubIssueUsage)
	}
	flags := flag.NewFlagSet("hub owner-bootstrap-issue", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	candidatePath := flags.String("candidate-manifest", "", "Owner signer public manifest received independently")
	fingerprint := flags.String("candidate-fingerprint", "", "exact full candidate public identity SHA-256 fingerprint")
	pairPath := flags.String("pair-file", "", "new mode 0600 Owner bootstrap pairing file")
	stateDir := flags.String("state-dir", "", "Hub StateDir (defaults to CICADA_STATE_DIR or /state)")
	workspaceRoot := flags.String("workspace-root", "", "Hub workspace root (defaults to CICADA_WORKSPACE_ROOT or /workspace)")
	if err := flags.Parse(args); err != nil || len(flags.Args()) != 0 || *candidatePath == "" || *fingerprint == "" || *pairPath == "" {
		return errors.New(hubIssueUsage)
	}
	var candidate ownersigner.PublicManifest
	if err := readStrictPublicJSON(*candidatePath, 128*1024, &candidate); err != nil {
		return errors.New("Owner signer candidate manifest is invalid")
	}
	if candidate.Format != "cicada.owner-signer-public.v1" || e2ee.ValidatePublicIdentity(candidate.OwnerPublic) != nil ||
		candidate.Fingerprint != ownerbootstrap.Fingerprint(candidate.OwnerPublic) || candidate.Fingerprint != strings.TrimSpace(*fingerprint) {
		return errors.New("candidate full public identity does not match the exact independently reviewed fingerprint")
	}
	if err := candidateConnectionMatches(candidate); err != nil {
		return err
	}
	config := hubControlConfig(*stateDir, *workspaceRoot)
	startup, err := store.AcquireStateStartup(config.StateDir)
	if err != nil {
		return err
	}
	defer startup.Close()
	persistence, err := store.New(filepath.Join(config.StateDir, "cicada.sqlite3"))
	if err != nil {
		return err
	}
	defer persistence.Close()
	preflight, preflightErr := persistence.CheckOwnerBootstrapIssueLocal()
	if preflightErr != nil {
		return preflightErr
	}
	if candidate.AccountID != preflight.AccountID || candidate.OwnerID != preflight.OwnerID || candidate.Origin != preflight.Origin || candidate.AllowLoopbackHTTP != preflight.AllowLoopbackHTTP || candidate.Hub.HubID != preflight.HubID {
		return store.ErrOwnerBootstrapRejected
	}
	identities, err := hubIssuerIdentities(config, persistence)
	if err != nil {
		return err
	}
	hubOwner, err := hubowner.NewService(persistence, identities)
	if err != nil {
		return err
	}
	setup, err := hubOwner.HubOwnerSetup()
	if err != nil || setup == nil || setup.State != store.HubOwnerReady || setup.RootEverEstablished {
		return store.ErrOwnerBootstrapRejected
	}
	hubID, err := hubOwner.ClientHubID()
	if err != nil {
		return err
	}
	currentHub := clientoperator.HubIdentity{Contract: "android-hub-v1", HubID: hubID,
		Public: hubOwner.ClientControlPublicIdentity(), KeyVersion: 1, Suite: clientoperator.Suite}
	if candidate.AccountID != setup.AccountID || candidate.OwnerID != setup.OwnerID || candidate.Origin != setup.Origin || candidate.AllowLoopbackHTTP != setup.AllowLoopbackHTTP ||
		candidate.Hub.HubID != setup.HubID || !reflect.DeepEqual(candidate.Hub, currentHub) ||
		candidate.Origin == "" || candidate.OwnerPublic.ID == currentHub.Public.ID {
		return errors.New("Owner signer candidate does not match the complete saved account, Owner, origin, and Hub pin")
	}
	if err := hubBootstrapIssueReview(input, output, candidate); err != nil {
		return err
	}
	pair, err := hubOwner.IssueOwnerBootstrapLocal(candidate.OwnerPublic, candidate.Fingerprint)
	if err != nil {
		return err
	}
	if err := persistence.Close(); err != nil {
		return err
	}
	encoded, err := json.MarshalIndent(pair, "", "  ")
	if err != nil {
		return err
	}
	encoded = append(encoded, '\n')
	if err := writePrivateExclusiveOrSame(*pairPath, encoded); err != nil {
		return err
	}
	return json.NewEncoder(output).Encode(struct {
		State                string `json:"state"`
		AccountID            string `json:"account_id"`
		OwnerID              string `json:"owner_id"`
		HubID                string `json:"hub_id"`
		Origin               string `json:"origin"`
		CandidateFingerprint string `json:"candidate_fingerprint"`
		ExpiresAt            string `json:"expires_at"`
		PairFile             string `json:"pair_file"`
	}{"PAIRING_ISSUED", pair.Manifest.AccountID, pair.Manifest.OwnerID, pair.Manifest.HubID,
		pair.Origin, pair.Manifest.CandidateFingerprint, pair.Manifest.ExpiresAt, *pairPath})
}

func candidateConnectionMatches(candidate ownersigner.PublicManifest) error {
	if candidate.Format != "cicada.owner-signer-public.v1" || e2ee.ValidatePublicIdentity(candidate.OwnerPublic) != nil ||
		candidate.Fingerprint != ownerbootstrap.Fingerprint(candidate.OwnerPublic) {
		return errors.New("Owner signer public manifest identity or full fingerprint is invalid")
	}
	connection := ownersigner.ConnectionFile{
		Format: ownersigner.ConnectionFileFormat, Version: 1, Purpose: ownersigner.ConnectionFilePurpose,
		AccountID: candidate.AccountID, OwnerID: candidate.OwnerID, Origin: candidate.Origin,
		AllowLoopbackHTTP: candidate.AllowLoopbackHTTP, Hub: candidate.Hub,
	}
	if err := connection.Validate(); err != nil {
		return errors.New("Owner signer public manifest lacks valid complete Hub setup context")
	}
	return nil
}

func hubBootstrapIssueReview(input io.Reader, output io.Writer, candidate ownersigner.PublicManifest) error {
	if !safeReviewID(candidate.AccountID) || !safeReviewID(candidate.OwnerID) || !safeReviewID(candidate.Hub.HubID) ||
		!safeReviewID(candidate.OwnerPublic.ID) || !validFingerprint(candidate.Fingerprint) ||
		!safeTerminalText(candidate.Origin) || candidate.Fingerprint != ownerbootstrap.Fingerprint(candidate.OwnerPublic) {
		return errors.New("Hub bootstrap review contains unsafe or invalid public identity fields")
	}
	in, ok := input.(*os.File)
	if !ok || !isatty.IsTerminal(in.Fd()) {
		return errors.New("Hub bootstrap issuance requires an interactive terminal")
	}
	out, ok := output.(*os.File)
	if !ok || !isatty.IsTerminal(out.Fd()) {
		return errors.New("Hub bootstrap review must be visible on an interactive terminal")
	}
	fmt.Fprintf(output, "Review the exact first Owner bootstrap candidate before the Hub records a challenge:\nAccount: %s\nOwner: %s\nHub: %s\nOrigin: %s\nCandidate key ID: %s\nCandidate full public fingerprint: %s\nPurpose: %s\nType `approve %s` to issue this ten-minute challenge: ",
		candidate.AccountID, candidate.OwnerID, candidate.Hub.HubID, candidate.Origin,
		candidate.OwnerPublic.ID, candidate.Fingerprint, ownerbootstrap.Purpose, candidate.Fingerprint)
	line, err := bufio.NewReader(io.LimitReader(input, 512)).ReadString('\n')
	if err != nil || strings.TrimSpace(line) != "approve "+candidate.Fingerprint {
		return errors.New("Hub bootstrap candidate was not approved with the exact full fingerprint")
	}
	return nil
}

func safeReviewID(value string) bool {
	if value == "" || len(value) > 128 || !utf8.ValidString(value) || strings.TrimSpace(value) != value {
		return false
	}
	for _, r := range value {
		if unicode.IsControl(r) || unicode.IsSpace(r) || unicode.Is(unicode.Cf, r) || r == '\u2028' || r == '\u2029' || strings.ContainsRune("/\\", r) {
			return false
		}
	}
	return true
}

func safeTerminalText(value string) bool {
	if !utf8.ValidString(value) {
		return false
	}
	for _, r := range value {
		if unicode.IsControl(r) || unicode.Is(unicode.Cf, r) || r == '\u2028' || r == '\u2029' {
			return false
		}
	}
	return true
}

func validFingerprint(value string) bool {
	if len(value) != 64 {
		return false
	}
	for _, r := range value {
		if !(r >= '0' && r <= '9') && !(r >= 'a' && r <= 'f') {
			return false
		}
	}
	return true
}

func hubControlConfig(stateDir, workspaceRoot string) control.Config {
	config := control.DefaultConfig()
	if stateDir != "" {
		config.StateDir = stateDir
	}
	if workspaceRoot != "" {
		config.WorkspaceRoot = workspaceRoot
	}
	return config
}

// checkHubServeReadiness runs before Control.New, because New may generate a
// compatibility manager identity. A new deployment must explicitly initialize
// a distinct Hub Owner; a legacy deployment must prove its exact old identity.
func checkHubServeReadiness(config control.Config) error {
	startup, err := store.AcquireStateStartup(config.StateDir)
	if err != nil {
		return err
	}
	defer startup.Close()
	identityPath := config.IdentityFile
	if identityPath == "" {
		identityPath = filepath.Join(config.StateDir, "e2ee", "identity.json")
	}
	legacyID := ""
	if _, err := os.Lstat(identityPath); err == nil {
		data, readErr := clientoperator.ReadPrivateFile(identityPath, 32*1024)
		if readErr != nil {
			return errors.New("existing Hub identity must be a regular mode 0600 file without symlinks")
		}
		identity, decodeErr := e2ee.UnmarshalIdentity(data)
		if decodeErr != nil || e2ee.ValidatePublicIdentity(identity.Public()) != nil {
			return errors.New("existing Hub identity is invalid; no replacement was generated")
		}
		legacyID = identity.Public().ID
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	persistence, err := store.New(filepath.Join(config.StateDir, "cicada.sqlite3"))
	if err != nil {
		return err
	}
	checkErr := persistence.CheckHubServeSetupLocal(legacyID)
	closeErr := persistence.Close()
	if checkErr != nil {
		return fmt.Errorf("Hub Owner readiness check failed; run `cicada hub setup` before serving: %w", checkErr)
	}
	return closeErr
}

func readStrictPublicJSON(path string, max int64, dst any) error {
	data, err := readPublicFile(path, max)
	if err != nil {
		return err
	}
	return decodeStrictBridgeJSON(data, dst)
}

func readPublicFile(path string, max int64) ([]byte, error) {
	abs, err := filepath.Abs(path)
	if err != nil {
		return nil, err
	}
	resolved, err := filepath.EvalSymlinks(abs)
	if err != nil || resolved != abs {
		return nil, errors.New("public file path must not contain symlink components")
	}
	info, err := os.Lstat(abs)
	if err != nil || !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 {
		return nil, errors.New("public file must be a regular file")
	}
	f, err := os.Open(abs)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	opened, err := f.Stat()
	if err != nil || !os.SameFile(info, opened) {
		return nil, errors.New("public file changed during open")
	}
	data, err := io.ReadAll(io.LimitReader(f, max+1))
	if err != nil || len(data) == 0 || int64(len(data)) > max {
		return nil, errors.New("public file has invalid size")
	}
	return data, nil
}

func writePublicExclusiveOrSame(path string, data []byte) error {
	return writeExclusiveOrSame(path, data, 0644)
}

func writePrivateExclusiveOrSame(path string, data []byte) error {
	return writeExclusiveOrSame(path, data, 0600)
}

func writeExclusiveOrSame(path string, data []byte, mode os.FileMode) error {
	abs, err := filepath.Abs(path)
	if err != nil {
		return err
	}
	parent := filepath.Dir(abs)
	resolvedParent, err := filepath.EvalSymlinks(parent)
	if err != nil || resolvedParent != parent {
		return errors.New("output parent must exist without symlink components")
	}
	if existing, err := readAnyRegular(abs, 256*1024, mode); err == nil {
		if bytes.Equal(existing, data) {
			return nil
		}
		return errors.New("output file already exists with different content")
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	tmp, err := os.CreateTemp(parent, ".cicada-owner-setup-*")
	if err != nil {
		return err
	}
	tmpPath := tmp.Name()
	defer os.Remove(tmpPath)
	if err = tmp.Chmod(mode); err == nil {
		_, err = tmp.Write(data)
	}
	if err == nil {
		err = tmp.Sync()
	}
	err = errors.Join(err, tmp.Close())
	if err != nil {
		return errors.New("could not persist output file")
	}
	if err := os.Link(tmpPath, abs); err != nil {
		return fmt.Errorf("create output file without overwrite: %w", err)
	}
	if err := os.Remove(tmpPath); err != nil {
		return err
	}
	dir, err := os.Open(parent)
	if err != nil {
		return err
	}
	return errors.Join(dir.Sync(), dir.Close())
}

func readAnyRegular(path string, max int64, mode os.FileMode) ([]byte, error) {
	info, err := os.Lstat(path)
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm() != mode {
		return nil, errors.New("existing output is not a regular file")
	}
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	opened, err := f.Stat()
	if err != nil || !os.SameFile(info, opened) {
		return nil, errors.New("existing output changed during open")
	}
	data, err := io.ReadAll(io.LimitReader(f, max+1))
	if err != nil || int64(len(data)) > max {
		return nil, errors.New("existing output has invalid size")
	}
	return data, nil
}

func writePrivateExclusive(path string, data []byte) error {
	if len(data) == 0 {
		return errors.New("refusing to write an empty Owner grant")
	}
	return writeExclusiveOrSame(path, data, 0600)
}

func hubAccountClaimIssueCommand(args []string, input io.Reader, output io.Writer) error {
	flags := flag.NewFlagSet("hub account-claim-issue", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	stateDir := flags.String("state-dir", "", "Hub StateDir")
	path := flags.String("claim-file", "", "new protected local claim-card file (never a URL)")
	appCodePath := flags.String("app-code-file", "", "new protected compact native App activation-code file")
	cancel := flags.Bool("cancel-pending", false, "explicitly cancel uncompleted prior claim before issuing")
	show := flags.Bool("show-code-card", false, "display claim card only on a real local terminal")
	showAppCode := flags.Bool("show-app-code", false, "display compact App activation code only on a real local terminal")
	if e := flags.Parse(args); e != nil || len(flags.Args()) != 0 || *path == "" || output == nil {
		return errors.New("usage: cicada hub account-claim-issue --claim-file NEW_0600_FILE [--app-code-file NEW_0600_FILE] [--state-dir DIR] [--cancel-pending] [--show-code-card|--show-app-code]")
	}
	if *show && *showAppCode {
		return errors.New("choose either --show-code-card or --show-app-code")
	}
	if (*show || *showAppCode) && !isReviewTerminal(input, output) {
		return errors.New("code-card display requires a real terminal")
	}
	abs, e := preflightPrivateOutput(*path, "claim")
	if e != nil {
		return e
	}
	appAbs := ""
	if *appCodePath != "" {
		appAbs, e = preflightPrivateOutput(*appCodePath, "App activation-code")
		if e != nil {
			return e
		}
		if appAbs == abs {
			return errors.New("claim-card and App-code outputs must use different files")
		}
	}
	config := hubControlConfig(*stateDir, "")
	startup, e := store.AcquireStateStartup(config.StateDir)
	if e != nil {
		return e
	}
	defer startup.Close()
	db, e := store.New(filepath.Join(config.StateDir, "cicada.sqlite3"))
	if e != nil {
		return e
	}
	defer db.Close()
	setup, _, e := db.HubAccountSetup()
	if e != nil || setup.RootEverEstablished {
		return store.ErrHubAccountRejected
	}
	if _, e = db.HubAccountCredential(setup.AccountID); e == nil {
		return store.ErrHubAccountRejected
	}
	ids, e := hubIssuerIdentities(config, db)
	if e != nil {
		return e
	}
	service, e := hubauth.NewService(db, ids)
	if e != nil {
		return e
	}
	card, e := service.IssueClaimLocal(*cancel)
	if e != nil {
		return e
	}
	raw, e := json.Marshal(card)
	if e != nil {
		return e
	}
	defer clear(raw)
	appCode, e := wire.EncodeOwnerAccountClaimCode(*card)
	if e != nil {
		return errors.New("native App activation code could not be encoded")
	}
	appCodeBytes := []byte(appCode + "\n")
	defer clear(appCodeBytes)
	defer func() { appCode = "" }()
	if e = writePrivateExclusive(abs, raw); e != nil {
		return errors.New("claim file could not be persisted; explicitly cancel pending claim before retrying")
	}
	if appAbs != "" {
		if e = writePrivateExclusive(appAbs, appCodeBytes); e != nil {
			return errors.New("App activation code could not be persisted; recover it from the protected claim-card file")
		}
	}
	if *show {
		_, e = fmt.Fprintf(output, "%s\n", raw)
		return e
	}
	if *showAppCode {
		_, e = fmt.Fprintf(output, "%s\n", appCode)
		return e
	}
	result := map[string]string{"state": "INITIAL_ACCOUNT_CLAIM_ISSUED", "origin": card.Origin, "claim_file": abs}
	if appAbs != "" {
		result["app_code_file"] = appAbs
	}
	return json.NewEncoder(output).Encode(result)
}

func preflightPrivateOutput(path, label string) (string, error) {
	abs, err := filepath.Abs(path)
	if err != nil {
		return "", err
	}
	parent := filepath.Dir(abs)
	resolved, err := filepath.EvalSymlinks(parent)
	if err != nil || resolved != parent {
		return "", fmt.Errorf("%s file requires an existing protected directory without symlinks", label)
	}
	info, err := os.Lstat(parent)
	if err != nil || !info.IsDir() || info.Mode().Perm() != 0700 {
		return "", fmt.Errorf("%s file directory must have mode 0700", label)
	}
	if _, err := os.Lstat(abs); !errors.Is(err, os.ErrNotExist) {
		return "", fmt.Errorf("%s output already exists or cannot be checked", label)
	}
	return abs, nil
}
func isReviewTerminal(input io.Reader, output io.Writer) bool {
	in, ok := input.(*os.File)
	if !ok || in == nil {
		return false
	}
	out, ok := output.(*os.File)
	return ok && out != nil && isatty.IsTerminal(in.Fd()) && isatty.IsTerminal(out.Fd())
}
