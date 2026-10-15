// two_owner_node_fixture creates a synthetic, authorization-only Endpoint on
// a disposable fixed-version Hub. This does not claim to prove a native
// Harness or Codex session.
package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/cicada-ai/cicada/internal/e2ee"
)

// Set by the fixed-source build script; never infer provenance from a worktree.
var sourceCommit = "UNSET"

type spec struct {
	SchemaVersion          int    `json:"schema_version"`
	HubBaseURL             string `json:"hub_base_url"`
	GroupID                string `json:"group_id"`
	NodeCredentialFile     string `json:"node_credential_file"`
	NativeSessionID        string `json:"native_session_id"`
	Workspace              string `json:"workspace"`
	EndpointPrivateKeyFile string `json:"endpoint_private_key_file"`
	PublicResultFile       string `json:"public_result_file"`
	Refresh                bool   `json:"refresh,omitempty"`
	LeaseSeconds           int    `json:"lease_seconds,omitempty"`
}

type endpoint struct {
	ID        string `json:"endpoint_id"`
	Principal string `json:"principal_id"`
	OwnerID   string `json:"owner"`
	NodeID    string `json:"machine_id"`
	Harness   string `json:"harness"`
	NativeID  string `json:"native_session_id"`
}

type joinResult struct {
	Endpoint       endpoint `json:"endpoint"`
	SessionToken   string   `json:"session_token"`
	BindingID      string   `json:"binding_id"`
	BindingEpoch   uint64   `json:"binding_epoch"`
	LeaseExpiresAt string   `json:"lease_expires_at"`
	Reused         bool     `json:"reused"`
}

type networkCard struct {
	PrincipalID     string `json:"principal_id"`
	EndpointID      string `json:"endpoint_id"`
	GroupID         string `json:"group_id"`
	NodeID          string `json:"node_id"`
	NativeSessionID string `json:"native_session_id"`
	BindingID       string `json:"binding_id"`
	BindingEpoch    uint64 `json:"binding_epoch"`
	BindingStatus   string `json:"binding_status"`
}

type candidate struct {
	EndpointID   string              `json:"endpoint_id"`
	PrincipalID  string              `json:"principal_id"`
	OwnerID      string              `json:"owner_id"`
	NodeID       string              `json:"node_id"`
	Public       e2ee.PublicIdentity `json:"public_identity"`
	KeyID        string              `json:"key_id"`
	BindingID    string              `json:"binding_id"`
	BindingEpoch uint64              `json:"binding_epoch"`
	Proof        []byte              `json:"proof"`
	ProofDigest  string              `json:"proof_digest"`
	State        string              `json:"state"`
	Version      int64               `json:"version"`
	CreatedAt    string              `json:"created_at"`
	UpdatedAt    string              `json:"updated_at"`
}

type publicResult struct {
	SchemaVersion   int       `json:"schema_version"`
	SourceCommit    string    `json:"source_commit"`
	FixtureKind     string    `json:"fixture_kind"`
	HubBaseURL      string    `json:"hub_base_url"`
	GroupID         string    `json:"group_id"`
	OwnerID         string    `json:"owner_id"`
	NodeID          string    `json:"node_id"`
	PrincipalID     string    `json:"principal_id"`
	EndpointID      string    `json:"endpoint_id"`
	NativeSessionID string    `json:"native_session_id"`
	BindingID       string    `json:"binding_id"`
	BindingEpoch    uint64    `json:"binding_epoch"`
	BindingStatus   string    `json:"binding_status"`
	LeaseExpiresAt  string    `json:"lease_expires_at"`
	KeyID           string    `json:"key_id"`
	Candidate       candidate `json:"candidate"`
}

func main() {
	specPath := flag.String("spec", "", "private JSON input spec (path only; no credential values on argv)")
	flag.Parse()
	if *specPath == "" || flag.NArg() != 0 {
		fmt.Fprintln(os.Stderr, "usage: two-owner-node-fixture -spec /private/path/owner-a.json")
		os.Exit(2)
	}
	if err := run(*specPath); err != nil {
		fmt.Fprintln(os.Stderr, "two-owner synthetic Endpoint fixture failed:", err)
		os.Exit(1)
	}
}

func run(specPath string) error {
	if !filepath.IsAbs(specPath) || filepath.Clean(specPath) != specPath {
		return errors.New("spec path must be absolute and cleaned")
	}
	if err := requirePrivateParent(filepath.Dir(specPath)); err != nil {
		return fmt.Errorf("spec parent directory: %w", err)
	}
	if err := requireOutsideGitWorktree(specPath); err != nil {
		return err
	}
	input, err := readPrivateFile(specPath, 64*1024)
	if err != nil {
		return fmt.Errorf("read private fixture spec: %w", err)
	}
	var cfg spec
	decoder := json.NewDecoder(bytes.NewReader(input))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&cfg); err != nil {
		return fmt.Errorf("decode fixture spec: %w", err)
	}
	if err := requireEOF(decoder); err != nil {
		return err
	}
	if err := validateSpec(&cfg); err != nil {
		return err
	}
	if cfg.LeaseSeconds == 0 {
		cfg.LeaseSeconds = 3600
	}

	if _, err := os.Lstat(cfg.PublicResultFile); err == nil && !cfg.Refresh {
		return errors.New("public result already exists; set refresh=true only when reusing the same synthetic session")
	} else if err != nil && !errors.Is(err, os.ErrNotExist) {
		return errors.New("cannot inspect public result path")
	}
	var previous *publicResult
	if cfg.Refresh {
		previous, err = readPriorResult(cfg.PublicResultFile)
		if err != nil {
			return err
		}
		if previous.GroupID != cfg.GroupID || previous.NativeSessionID != cfg.NativeSessionID ||
			previous.HubBaseURL != strings.TrimRight(cfg.HubBaseURL, "/") || previous.SourceCommit != sourceCommit {
			return errors.New("refresh spec does not match the prior Group, native session, Hub, or source commit")
		}
	}

	nodeToken, err := readNodeCredential(cfg.NodeCredentialFile)
	if err != nil {
		return err
	}
	identity, err := loadOrCreateEndpointIdentity(cfg.EndpointPrivateKeyFile)
	if err != nil {
		return err
	}
	if previous != nil && previous.Candidate.Public.ID != identity.Public().ID {
		return errors.New("refresh Endpoint private key does not match the previously published public identity")
	}
	client := &http.Client{Timeout: 30 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error {
		return http.ErrUseLastResponse
	}}
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()

	joinBody, err := json.Marshal(map[string]any{
		"group_id":          cfg.GroupID,
		"harness":           "codex",
		"native_session_id": cfg.NativeSessionID,
		"workspace":         cfg.Workspace,
		"lease_seconds":     cfg.LeaseSeconds,
	})
	if err != nil {
		return errors.New("encode supported Node Join request")
	}
	var joined joinResult
	if err := doJSON(ctx, client, cfg.HubBaseURL, http.MethodPost, "/v2/fabric/node/join", http.StatusCreated, "CicadaNode "+nodeToken, "", joinBody, &joined); err != nil {
		return fmt.Errorf("Node-authenticated synthetic Join: %w", err)
	}
	if joined.SessionToken == "" || joined.Endpoint.ID == "" || joined.Endpoint.Principal == "" ||
		joined.Endpoint.OwnerID == "" ||
		joined.Endpoint.NodeID == "" || joined.BindingID == "" || joined.BindingEpoch == 0 {
		return errors.New("Node Join returned incomplete identity or lease coordinates")
	}
	leaseExpiry, err := time.Parse(time.RFC3339Nano, joined.LeaseExpiresAt)
	if err != nil || !leaseExpiry.After(time.Now()) {
		return errors.New("Node Join returned an expired or invalid binding lease")
	}
	// The Session bearer remains in memory only. It is never printed or written.

	var card networkCard
	if err := doJSON(ctx, client, cfg.HubBaseURL, http.MethodGet, "/v2/fabric/whoami", http.StatusOK, "CicadaSession "+joined.SessionToken, cfg.GroupID, nil, &card); err != nil {
		return fmt.Errorf("verify joined Session with whoami: %w", err)
	}
	if card.GroupID != cfg.GroupID || card.EndpointID != joined.Endpoint.ID ||
		card.PrincipalID != joined.Endpoint.Principal || card.NodeID != joined.Endpoint.NodeID ||
		card.BindingID != joined.BindingID || card.BindingEpoch != joined.BindingEpoch ||
		card.NativeSessionID != cfg.NativeSessionID {
		return errors.New("authenticated whoami coordinates differ from Node Join response")
	}
	if previous != nil {
		if card.EndpointID != previous.EndpointID || card.PrincipalID != previous.PrincipalID ||
			card.NodeID != previous.NodeID || card.BindingID != previous.BindingID ||
			card.BindingEpoch <= previous.BindingEpoch {
			return errors.New("refresh did not preserve Endpoint identity and advance its binding epoch")
		}
	}

	proof, err := identity.SignEndpointKeyAttestation(card.EndpointID, card.PrincipalID,
		card.NodeID, card.BindingID, card.BindingEpoch)
	if err != nil {
		return fmt.Errorf("sign fixed-contract ML-DSA Endpoint attestation: %w", err)
	}
	wrappedProof, err := json.Marshal(struct {
		Attestation json.RawMessage `json:"attestation"`
	}{Attestation: proof})
	if err != nil {
		return errors.New("encode Endpoint attestation request")
	}
	var published candidate
	if err := doJSON(ctx, client, cfg.HubBaseURL, http.MethodPost, "/v2/fabric/endpoint-keys", http.StatusOK,
		"CicadaSession "+joined.SessionToken, cfg.GroupID, wrappedProof, &published); err != nil {
		return fmt.Errorf("publish self-attested public candidate: %w", err)
	}
	if published.State != "CANDIDATE" || published.EndpointID != card.EndpointID ||
		published.PrincipalID != card.PrincipalID || published.OwnerID != joined.Endpoint.OwnerID || published.NodeID != card.NodeID ||
		published.BindingID != card.BindingID || published.BindingEpoch != card.BindingEpoch ||
		published.KeyID != identity.Public().ID || !publicIdentityEqual(published.Public, identity.Public()) ||
		!bytes.Equal(published.Proof, proof) || published.ProofDigest != proofDigest(proof) {
		return errors.New("Hub candidate does not match the authenticated Endpoint and public identity")
	}
	if previous != nil && published.KeyID != previous.KeyID {
		return errors.New("refresh changed the public Endpoint key identifier")
	}
	if previous != nil && published.OwnerID != previous.OwnerID {
		return errors.New("refresh changed the Endpoint Owner")
	}

	result := publicResult{
		SchemaVersion: 1, SourceCommit: sourceCommit,
		FixtureKind: "SYNTHETIC_ENDPOINT_AUTHORIZATION_ONLY_NOT_NATIVE_EVIDENCE",
		HubBaseURL:  strings.TrimRight(cfg.HubBaseURL, "/"), GroupID: card.GroupID, OwnerID: published.OwnerID,
		NodeID: card.NodeID, PrincipalID: card.PrincipalID, EndpointID: card.EndpointID,
		NativeSessionID: card.NativeSessionID, BindingID: card.BindingID,
		BindingEpoch: card.BindingEpoch, BindingStatus: card.BindingStatus,
		LeaseExpiresAt: joined.LeaseExpiresAt, KeyID: published.KeyID, Candidate: published,
	}
	resultBytes, err := json.Marshal(result)
	if err != nil {
		return errors.New("encode public-only result")
	}
	if bytes.Contains(resultBytes, []byte(joined.SessionToken)) ||
		bytes.Contains(resultBytes, []byte(nodeToken)) {
		return errors.New("refusing to persist a result containing a bearer credential")
	}
	if err := writePrivateJSON(cfg.PublicResultFile, result); err != nil {
		return fmt.Errorf("write public-only result: %w", err)
	}
	if previous == nil {
		fmt.Printf("synthetic Endpoint candidate published: endpoint=%s node=%s binding_epoch=%d state=CANDIDATE\n",
			card.EndpointID, card.NodeID, card.BindingEpoch)
	} else {
		fmt.Printf("synthetic Endpoint candidate refreshed: endpoint=%s node=%s binding_epoch=%d state=CANDIDATE\n",
			card.EndpointID, card.NodeID, card.BindingEpoch)
	}
	return nil
}

func validateSpec(cfg *spec) error {
	if cfg.SchemaVersion != 1 || strings.TrimSpace(cfg.GroupID) == "" ||
		strings.TrimSpace(cfg.NativeSessionID) == "" || strings.TrimSpace(cfg.Workspace) == "" {
		return errors.New("spec requires schema_version=1, group_id, native_session_id, and workspace")
	}
	if !safeIdentifier(cfg.GroupID) || !safeIdentifier(cfg.NativeSessionID) {
		return errors.New("group_id and native_session_id must contain only letters, digits, dot, underscore, colon, or hyphen")
	}
	if cfg.LeaseSeconds < 0 || cfg.LeaseSeconds > 3600 {
		return errors.New("lease_seconds must be between 0 and 3600")
	}
	parsed, err := url.Parse(strings.TrimSpace(cfg.HubBaseURL))
	if err != nil || parsed == nil || parsed.Hostname() == "" || parsed.User != nil ||
		parsed.RawQuery != "" || parsed.Fragment != "" ||
		(parsed.Path != "" && parsed.Path != "/") || (parsed.Scheme != "http" && parsed.Scheme != "https") || parsed.Port() == "" {
		return errors.New("hub_base_url must be a loopback origin URL with an explicit port and no credentials, path, query, or fragment")
	}
	port, err := strconv.Atoi(parsed.Port())
	ip := net.ParseIP(parsed.Hostname())
	if err != nil || port < 1 || port > 65535 || ip == nil || !ip.IsLoopback() {
		return errors.New("hub_base_url must use literal 127.0.0.1 or [::1] with a valid explicit port")
	}
	for label, path := range map[string]string{
		"node_credential_file":      cfg.NodeCredentialFile,
		"endpoint_private_key_file": cfg.EndpointPrivateKeyFile,
		"public_result_file":        cfg.PublicResultFile,
	} {
		if !filepath.IsAbs(path) || filepath.Clean(path) != path {
			return fmt.Errorf("%s must be an absolute, cleaned path outside the repository", label)
		}
		if err := requirePrivateParent(filepath.Dir(path)); err != nil {
			return fmt.Errorf("%s parent directory: %w", label, err)
		}
		if err := requireOutsideGitWorktree(path); err != nil {
			return fmt.Errorf("%s: %w", label, err)
		}
	}
	if !filepath.IsAbs(cfg.Workspace) {
		return errors.New("workspace must be an absolute synthetic workspace path")
	}
	return nil
}

func readNodeCredential(path string) (string, error) {
	data, err := readPrivateFile(path, 4096)
	if err != nil {
		return "", fmt.Errorf("read Node credential file: %w", err)
	}
	token := strings.TrimSpace(string(data))
	if !strings.HasPrefix(token, "cicada_node_") || strings.ContainsAny(token, " \t\r\n") {
		return "", errors.New("Node credential file is not a raw fixed-contract Node bearer")
	}
	return token, nil
}

func loadOrCreateEndpointIdentity(path string) (*e2ee.Identity, error) {
	data, err := readPrivateFile(path, 1<<20)
	if err == nil {
		identity, err := e2ee.UnmarshalIdentity(data)
		if err != nil {
			return nil, errors.New("stored Endpoint private identity is invalid")
		}
		return identity, nil
	}
	if !errors.Is(err, os.ErrNotExist) {
		return nil, fmt.Errorf("read Endpoint private identity: %w", err)
	}
	identity, err := e2ee.NewIdentity()
	if err != nil {
		return nil, errors.New("generate Endpoint ML-KEM/ML-DSA identity")
	}
	private, err := identity.MarshalBinary()
	if err != nil {
		return nil, errors.New("encode Endpoint private identity")
	}
	file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		if errors.Is(err, os.ErrExist) {
			return loadOrCreateEndpointIdentity(path)
		}
		return nil, errors.New("create external Endpoint private identity file")
	}
	if _, err := file.Write(private); err != nil {
		_ = file.Close()
		_ = os.Remove(path)
		return nil, errors.New("write external Endpoint private identity file")
	}
	if err := file.Sync(); err != nil {
		_ = file.Close()
		_ = os.Remove(path)
		return nil, errors.New("sync external Endpoint private identity file")
	}
	if err := file.Close(); err != nil {
		_ = os.Remove(path)
		return nil, errors.New("close external Endpoint private identity file")
	}
	return identity, nil
}

func readPrivateFile(path string, max int64) ([]byte, error) {
	info, err := os.Lstat(path)
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() || info.Mode().Perm() != 0o600 || info.Size() > max {
		return nil, errors.New("file must be regular, mode 0600, and within its size limit")
	}
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	return io.ReadAll(io.LimitReader(file, max+1))
}

func requirePrivateParent(path string) error {
	info, err := os.Lstat(path)
	if err != nil {
		return errors.New("directory must already exist")
	}
	if !info.IsDir() || info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm() != 0o700 {
		return errors.New("directory must be real and mode 0700")
	}
	return nil
}

func requireOutsideGitWorktree(path string) error {
	current, err := filepath.EvalSymlinks(filepath.Dir(filepath.Clean(path)))
	if err != nil {
		return errors.New("cannot resolve fixture file parent outside a Git worktree")
	}
	for {
		if _, err := os.Lstat(filepath.Join(current, ".git")); err == nil {
			return errors.New("spec, credential, key, and result files must be outside Git worktrees")
		} else if !errors.Is(err, os.ErrNotExist) {
			return errors.New("cannot verify that a fixture file is outside a Git worktree")
		}
		parent := filepath.Dir(current)
		if parent == current {
			return nil
		}
		current = parent
	}
}

func safeIdentifier(value string) bool {
	if len(value) == 0 || len(value) > 200 {
		return false
	}
	for _, char := range value {
		if (char >= 'a' && char <= 'z') || (char >= 'A' && char <= 'Z') ||
			(char >= '0' && char <= '9') || strings.ContainsRune("._:-", char) {
			continue
		}
		return false
	}
	return true
}

func doJSON(ctx context.Context, client *http.Client, base, method, path string, expectedStatus int,
	authorization, group string, body []byte, target any) error {
	var reader io.Reader
	if body != nil {
		reader = bytes.NewReader(body)
	}
	request, err := http.NewRequestWithContext(ctx, method, strings.TrimRight(base, "/")+path, reader)
	if err != nil {
		return errors.New("build fixed-contract Hub request")
	}
	request.Header.Set("Accept", "application/json")
	if authorization != "" {
		request.Header.Set("Authorization", authorization)
	}
	if group != "" {
		request.Header.Set("Cicada-Group-Scope", group)
	}
	if body != nil {
		request.Header.Set("Content-Type", "application/json")
	}
	response, err := client.Do(request)
	if err != nil {
		return errors.New("Hub request failed before an HTTP response")
	}
	defer response.Body.Close()
	if response.StatusCode != expectedStatus {
		return fmt.Errorf("Hub returned HTTP %d, want %d", response.StatusCode, expectedStatus)
	}
	if target == nil {
		_, _ = io.Copy(io.Discard, io.LimitReader(response.Body, 1<<20))
		return nil
	}
	decoder := json.NewDecoder(io.LimitReader(response.Body, 1<<20))
	if err := decoder.Decode(target); err != nil {
		return errors.New("Hub returned an invalid fixed-contract JSON response")
	}
	return nil
}

func publicIdentityEqual(left, right e2ee.PublicIdentity) bool {
	return left.ID == right.ID && bytes.Equal(left.KEMPublic, right.KEMPublic) &&
		bytes.Equal(left.SigningPublic, right.SigningPublic)
}

func proofDigest(proof []byte) string {
	sum := sha256.Sum256(proof)
	return hex.EncodeToString(sum[:])
}

func readPriorResult(path string) (*publicResult, error) {
	data, err := readPrivateFile(path, 8<<20)
	if err != nil {
		return nil, errors.New("refresh requires the existing mode-0600 public result file")
	}
	var prior publicResult
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&prior); err != nil || prior.SchemaVersion != 1 ||
		prior.SourceCommit != sourceCommit || prior.FixtureKind != "SYNTHETIC_ENDPOINT_AUTHORIZATION_ONLY_NOT_NATIVE_EVIDENCE" {
		return nil, errors.New("existing result is not a compatible synthetic fixture record")
	}
	return &prior, nil
}

func writePrivateJSON(path string, value any) error {
	data, err := json.MarshalIndent(value, "", "  ")
	if err != nil {
		return errors.New("encode public fixture result")
	}
	data = append(data, '\n')
	temporary, err := os.CreateTemp(filepath.Dir(path), ".two-owner-result-*")
	if err != nil {
		return errors.New("create protected result file")
	}
	name := temporary.Name()
	defer os.Remove(name)
	if err := temporary.Chmod(0o600); err != nil {
		_ = temporary.Close()
		return errors.New("protect result file")
	}
	if _, err := temporary.Write(data); err != nil {
		_ = temporary.Close()
		return errors.New("write result file")
	}
	if err := temporary.Sync(); err != nil {
		_ = temporary.Close()
		return errors.New("sync result file")
	}
	if err := temporary.Close(); err != nil {
		return errors.New("close result file")
	}
	if err := os.Rename(name, path); err != nil {
		return errors.New("install result file")
	}
	directory, err := os.Open(filepath.Dir(path))
	if err != nil {
		return errors.New("open result directory")
	}
	defer directory.Close()
	if err := directory.Sync(); err != nil {
		return errors.New("sync result directory")
	}
	return nil
}

func requireEOF(decoder *json.Decoder) error {
	var extra any
	if err := decoder.Decode(&extra); !errors.Is(err, io.EOF) {
		return errors.New("fixture spec contains trailing JSON data")
	}
	return nil
}
