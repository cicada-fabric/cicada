//go:build !windows

package ownersigner

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"testing"
	"time"

	"github.com/cicada-ai/cicada/internal/clientwire"
	"github.com/cicada-ai/cicada/internal/e2ee"
	"github.com/cicada-ai/cicada/internal/ownerbootstrap"
)

// This fixture is filesystem/state testing only. Its visibly mocked executable
// answers version and refuses every private operation. It is not OpenSSL
// cryptographic interoperability or native Windows/ACL acceptance evidence.
type externalMetadataFixture struct {
	root, dir  string
	paths      OpenSSLPaths
	connection ConnectionFile
	owner, hub *e2ee.Identity
	pemMarker  []byte
}

func newExternalMetadataFixture(t *testing.T) externalMetadataFixture {
	t.Helper()
	root := t.TempDir()
	hub, publicHub := testHubIdentity(t)
	owner, err := e2ee.NewIdentity()
	if err != nil {
		t.Fatal(err)
	}
	paths := OpenSSLPaths{Executable: filepath.Join(root, "PUBLIC_SYNTHETIC_MOCK_OPENSSL.sh"), KEMPrivate: filepath.Join(root, "synthetic-kem.pem"), SigningPrivate: filepath.Join(root, "synthetic-signing.pem")}
	script := []byte("#!/bin/sh\n# PUBLIC SYNTHETIC MOCK; NO PRIVATE CRYPTO OPERATIONS\ncase \"$1\" in\nversion) printf 'OpenSSL 3.5.9 PUBLIC_SYNTHETIC_MOCK\\n';;\n*) exit 99;;\nesac\n")
	if err := os.WriteFile(paths.Executable, script, 0700); err != nil {
		t.Fatal(err)
	}
	marker := []byte("PUBLIC SYNTHETIC TEST PEM CONTENT — NOT A KEY — NEVER USE IN A DEPLOYMENT")
	for _, path := range []string{paths.KEMPrivate, paths.SigningPrivate} {
		if err := os.WriteFile(path, marker, 0600); err != nil {
			t.Fatal(err)
		}
	}
	return externalMetadataFixture{root: root, dir: filepath.Join(root, "profile"), paths: paths, owner: owner, hub: hub, pemMarker: marker,
		connection: ConnectionFile{Format: ConnectionFileFormat, Version: 1, Purpose: ConnectionFilePurpose, AccountID: "synthetic_account", OwnerID: "synthetic_owner", Origin: "https://synthetic.invalid", Hub: publicHub}}
}

func (f externalMetadataFixture) prepare(t *testing.T) *ExternalProfile {
	t.Helper()
	p, err := PrepareExternal(f.dir, f.connection, f.owner.Public(), f.paths)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = p.Close() })
	return p
}

func (f externalMetadataFixture) pairAndProof(t *testing.T) (ownerbootstrap.PairingFile, []byte, []byte) {
	t.Helper()
	now := time.Date(2026, 10, 14, 0, 0, 0, 0, time.UTC)
	pair := ownerbootstrap.PairingFile{Format: ownerbootstrap.Format, Origin: f.connection.Origin,
		Hub:      ownerbootstrap.HubIdentity{Contract: f.connection.Hub.Contract, HubID: f.connection.Hub.HubID, Public: f.connection.Hub.Public, KeyVersion: 1, Suite: f.connection.Hub.Suite},
		Manifest: ownerbootstrap.Manifest{Version: 1, Purpose: ownerbootstrap.Purpose, AccountID: f.connection.AccountID, OwnerID: f.connection.OwnerID, HubID: f.connection.Hub.HubID, AuthorityID: "synthetic_authority", OperationID: "synthetic_bootstrap", CandidatePublic: f.owner.Public(), CandidateFingerprint: ownerbootstrap.Fingerprint(f.owner.Public()), ExpiresAt: now.Add(time.Minute).Format(time.RFC3339Nano)}}
	pair, _, err := ownerbootstrap.CreateChallenge(f.hub, pair, now)
	if err != nil {
		t.Fatal(err)
	}
	possession, err := ownerbootstrap.OpenChallengeWithPrivateOperations(f.owner.Public(), f.owner, pair, now)
	if err != nil {
		t.Fatal(err)
	}
	var body ownerbootstrap.Possession
	if json.Unmarshal(possession, &body) != nil {
		t.Fatal("decode synthetic possession")
	}
	clear(possession)
	proof, err := ownerbootstrap.CreateProof(f.owner, pair, now)
	if err != nil {
		t.Fatal(err)
	}
	return pair, proof, body.Nonce
}

func TestExternalOwnerMetadataFreshPrepareLockAndNoOverwrite(t *testing.T) {
	f := newExternalMetadataFixture(t)
	if _, err := os.Lstat(f.dir); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("fixture profile must start absent")
	}
	p := f.prepare(t)
	for path, want := range map[string]os.FileMode{f.dir: 0700, filepath.Join(f.dir, externalProfileFile): 0600, filepath.Join(f.dir, externalProfileLock): 0600} {
		info, err := os.Stat(path)
		if err != nil || info.Mode().Perm() != want {
			t.Fatalf("protected path mode: %s %v", filepath.Base(path), err)
		}
	}
	original, err := os.ReadFile(filepath.Join(f.dir, externalProfileFile))
	if err != nil {
		t.Fatal(err)
	}
	if second, err := PrepareExternal(f.dir, f.connection, f.owner.Public(), f.paths); err == nil {
		_ = second.Close()
		t.Fatal("prepare overwrote existing profile")
	}
	after, _ := os.ReadFile(filepath.Join(f.dir, externalProfileFile))
	if !bytes.Equal(original, after) {
		t.Fatal("failed prepare mutated existing metadata")
	}
	if second, err := OpenExternal(f.dir); !errors.Is(err, ErrBusy) {
		if second != nil {
			_ = second.Close()
		}
		t.Fatalf("second opener: %v", err)
	}
	exported, err := p.ExportManifest("")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := p.ExportManifest(""); err != nil {
		t.Fatalf("identical export retry: %v", err)
	}
	var manifest PublicManifest
	data, _ := os.ReadFile(exported)
	if json.Unmarshal(data, &manifest) != nil || !reflect.DeepEqual(manifest, p.PublicManifest()) {
		t.Fatal("public manifest lost complete pins")
	}
	if bytes.Contains(data, f.pemMarker) || bytes.Contains(data, []byte("owner_private_identity")) {
		t.Fatal("public export contains private material")
	}
	if err := p.Close(); err != nil {
		t.Fatal(err)
	}
	reopened, err := OpenExternal(f.dir)
	if err != nil {
		t.Fatal(err)
	}
	defer reopened.Close()
	if !reflect.DeepEqual(reopened.PublicManifest(), manifest) {
		t.Fatal("reopen changed Owner or Hub pins")
	}
}

func TestExternalOwnerMetadataRejectsUnsafeCustody(t *testing.T) {
	for _, kind := range []string{"directory_permissions", "metadata_permissions", "lock_permissions", "profile_symlink", "metadata_symlink", "lock_symlink", "native_format_collision", "missing_external_metadata"} {
		t.Run(kind, func(t *testing.T) {
			f := newExternalMetadataFixture(t)
			p := f.prepare(t)
			_ = p.Close()
			openPath := f.dir
			metadata := filepath.Join(f.dir, externalProfileFile)
			lock := filepath.Join(f.dir, externalProfileLock)
			switch kind {
			case "directory_permissions":
				if err := os.Chmod(f.dir, 0755); err != nil {
					t.Fatal(err)
				}
			case "metadata_permissions":
				if err := os.Chmod(metadata, 0644); err != nil {
					t.Fatal(err)
				}
			case "lock_permissions":
				if err := os.Chmod(lock, 0644); err != nil {
					t.Fatal(err)
				}
			case "profile_symlink":
				openPath = filepath.Join(f.root, "profile-link")
				if err := os.Symlink(f.dir, openPath); err != nil {
					t.Fatal(err)
				}
			case "metadata_symlink", "lock_symlink":
				path := metadata
				if kind == "lock_symlink" {
					path = lock
				}
				target := path + "-retained"
				if err := os.Rename(path, target); err != nil {
					t.Fatal(err)
				}
				if err := os.Symlink(target, path); err != nil {
					t.Fatal(err)
				}
			case "native_format_collision":
				if err := os.WriteFile(filepath.Join(f.dir, profileFileName), []byte("synthetic native marker"), 0600); err != nil {
					t.Fatal(err)
				}
			case "missing_external_metadata":
				if err := os.Remove(metadata); err != nil {
					t.Fatal(err)
				}
			}
			got, err := OpenExternal(openPath)
			if got != nil {
				_ = got.Close()
			}
			if err == nil || errors.Is(err, ErrNotExternalProfile) {
				t.Fatalf("unsafe external state accepted or fell through: %v", err)
			}
		})
	}
	for _, kind := range []string{"pem_permissions", "pem_symlink", "executable_symlink", "parent_symlink"} {
		t.Run("prepare_"+kind, func(t *testing.T) {
			f := newExternalMetadataFixture(t)
			switch kind {
			case "pem_permissions":
				if err := os.Chmod(f.paths.KEMPrivate, 0644); err != nil {
					t.Fatal(err)
				}
			case "pem_symlink", "executable_symlink":
				path := f.paths.KEMPrivate
				if kind == "executable_symlink" {
					path = f.paths.Executable
				}
				alias := path + "-link"
				if err := os.Symlink(path, alias); err != nil {
					t.Fatal(err)
				}
				if kind == "pem_symlink" {
					f.paths.KEMPrivate = alias
				} else {
					f.paths.Executable = alias
				}
			case "parent_symlink":
				alias := filepath.Join(f.root, "parent-link")
				if err := os.Symlink(f.root, alias); err != nil {
					t.Fatal(err)
				}
				f.dir = filepath.Join(alias, "profile")
			}
			got, err := PrepareExternal(f.dir, f.connection, f.owner.Public(), f.paths)
			if got != nil {
				_ = got.Close()
			}
			if err == nil {
				t.Fatal("unsafe preparation accepted")
			}
			if _, err := os.Lstat(filepath.Join(f.root, "profile")); !errors.Is(err, os.ErrNotExist) {
				t.Fatal("unsafe input created profile")
			}
		})
	}
}

func TestExternalOwnerMetadataPinsExecutableAndStrictJSON(t *testing.T) {
	f := newExternalMetadataFixture(t)
	p := f.prepare(t)
	_ = p.Close()
	original, err := os.ReadFile(f.paths.Executable)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(f.paths.Executable, append(original, []byte("\n# changed mock executable\n")...), 0700); err != nil {
		t.Fatal(err)
	}
	if got, err := OpenExternal(f.dir); err == nil {
		_ = got.Close()
		t.Fatal("changed executable accepted")
	}
	if err := os.WriteFile(f.paths.Executable, original, 0700); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(f.dir, externalProfileFile)
	stateBytes, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	for _, malformed := range [][]byte{[]byte("{"), append(append([]byte(nil), stateBytes...), []byte("{}")...), append([]byte(`{"unknown_private_seed":"PUBLIC_SYNTHETIC_TEST",`), stateBytes[1:]...)} {
		if err := os.WriteFile(path, malformed, 0600); err != nil {
			t.Fatal(err)
		}
		got, err := OpenExternal(f.dir)
		if got != nil {
			_ = got.Close()
		}
		if err == nil || errors.Is(err, ErrNotExternalProfile) {
			t.Fatalf("malformed metadata accepted or fell through: %v", err)
		}
	}
	if err := os.WriteFile(path, stateBytes, 0600); err != nil {
		t.Fatal(err)
	}
	reopened, err := OpenExternal(f.dir)
	if err != nil {
		t.Fatalf("failed opens leaked lock or altered good state: %v", err)
	}
	_ = reopened.Close()
}

func TestExternalOwnerMetadataCacheScopeAndSavedRoute(t *testing.T) {
	f := newExternalMetadataFixture(t)
	p := f.prepare(t)
	pair, proof, nonce := f.pairAndProof(t)
	defer clear(nonce)
	pairBytes, err := json.Marshal(pair)
	if err != nil {
		t.Fatal(err)
	}
	p.state.Bootstrap = &pendingBootstrap{PairFile: pairBytes, Proof: proof}
	if err := p.save(); err != nil {
		t.Fatal(err)
	}
	if err := p.Close(); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(f.dir, externalProfileFile)
	original, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	privateIdentity, err := f.owner.MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}
	defer clear(privateIdentity)
	for _, secret := range [][]byte{f.pemMarker, privateIdentity, nonce, []byte(base64.StdEncoding.EncodeToString(nonce)), []byte("owner_private_identity")} {
		if bytes.Contains(original, secret) {
			t.Fatal("profile persisted private PEM, identity, or plaintext possession nonce")
		}
	}
	mutations := map[string]func(*externalProfileState){
		"account": func(s *externalProfileState) { s.AccountID = "synthetic_other" },
		"owner":   func(s *externalProfileState) { s.OwnerID = "synthetic_other" },
		"origin":  func(s *externalProfileState) { s.Origin = "https://other.synthetic.invalid" },
		"hub_pin": func(s *externalProfileState) { s.Hub.Public = f.owner.Public() },
		"candidate": func(s *externalProfileState) {
			s.OwnerPublic = f.hub.Public()
			s.Fingerprint = ownerbootstrap.Fingerprint(s.OwnerPublic)
		},
		"fingerprint":     func(s *externalProfileState) { s.Fingerprint = ownerbootstrap.Fingerprint(f.hub.Public()) },
		"pair_malformed":  func(s *externalProfileState) { s.Bootstrap.PairFile = []byte("{") },
		"proof_malformed": func(s *externalProfileState) { s.Bootstrap.Proof = []byte("{") },
		"proof_empty":     func(s *externalProfileState) { s.Bootstrap.Proof = nil },
		"proof_sequence": func(s *externalProfileState) {
			var packet clientwire.Packet
			_ = json.Unmarshal(s.Bootstrap.Proof, &packet)
			packet.Route.Sequence++
			s.Bootstrap.Proof, _ = json.Marshal(packet)
		},
		"proof_operation": func(s *externalProfileState) {
			var packet clientwire.Packet
			_ = json.Unmarshal(s.Bootstrap.Proof, &packet)
			packet.Route.Operation = "synthetic.other"
			s.Bootstrap.Proof, _ = json.Marshal(packet)
		},
	}
	for name, mutate := range mutations {
		t.Run(name, func(t *testing.T) {
			var state externalProfileState
			if json.Unmarshal(original, &state) != nil {
				t.Fatal("fixture decode")
			}
			mutate(&state)
			raw, _ := json.Marshal(state)
			if err := os.WriteFile(path, raw, 0600); err != nil {
				t.Fatal(err)
			}
			got, err := OpenExternal(f.dir)
			if got != nil {
				_ = got.Close()
			}
			if err == nil || errors.Is(err, ErrNotExternalProfile) {
				t.Fatalf("changed cache scope accepted or fell through: %v", err)
			}
		})
	}
	if err := os.WriteFile(path, original, 0600); err != nil {
		t.Fatal(err)
	}
	reopened, err := OpenExternal(f.dir)
	if err != nil {
		t.Fatal(err)
	}
	defer reopened.Close()
	if !bytes.Equal(reopened.state.Bootstrap.PairFile, pairBytes) || !bytes.Equal(reopened.state.Bootstrap.Proof, proof) {
		t.Fatal("reopen mutated exact saved pairing/proof")
	}
	// A malformed cached response is not evidence of accepted Root authority.
	// Parsing and scope verification reject it; the mock never performs crypto.
	reopened.state.Bootstrap.Response = []byte("{")
	if _, err := reopened.Recover(context.Background(), nil); err == nil {
		t.Fatal("malformed cached receipt accepted")
	}
}
