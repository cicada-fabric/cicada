package nodetransport

import (
	"bytes"
	"context"
	"encoding/hex"
	"errors"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/cicada-ai/cicada/internal/e2ee"
	"github.com/cicada-ai/cicada/internal/nodekeys"
	"github.com/cicada-ai/cicada/internal/nodelock"
	"github.com/cicada-ai/cicada/internal/pqtls"
	"github.com/cicada-ai/cicada/internal/store"
)

func installPrivateDir(t *testing.T) string {
	t.Helper()
	p := t.TempDir()
	if os.Chmod(p, 0700) != nil {
		t.Fatal("private test directory")
	}
	return p
}
func installSyntheticLocal(t *testing.T) (*LocalTLSInstaller, *e2ee.Identity, *e2ee.Identity, TLSLocalBinding) {
	t.Helper()
	owner, e := e2ee.NewIdentity()
	if e != nil {
		t.Fatal(e)
	}
	node, e := e2ee.NewIdentity()
	if e != nil {
		t.Fatal(e)
	}
	hub, e := e2ee.NewIdentity()
	if e != nil {
		t.Fatal(e)
	}
	trust, e := nodekeys.OpenCryptoState(installPrivateDir(t))
	if e != nil {
		t.Fatal(e)
	}
	t.Cleanup(func() { trust.Close() })
	fp, e := nodekeys.PeerKeyFingerprint(owner.Public())
	if e != nil {
		t.Fatal(e)
	}
	if _, e = trust.TrustOwnerApprovalKeyLocal("synthetic-owner", owner.Public().ID, owner.Public(), fp); e != nil {
		t.Fatal(e)
	}
	b := TLSLocalBinding{Control: store.NodeControlKeyBinding{OwnerBindingID: "synthetic-binding", OwnerID: "synthetic-owner", HubID: "synthetic-hub", NodeID: "synthetic-node", ClientDeviceID: "synthetic-device", OwnerKeyID: owner.Public().ID, NodeCredentialVersion: 1, BindingVersion: 1, NodeKeyID: node.Public().ID, NodePublicIdentity: node.Public(), NodeKeyVersion: 1, NodeKeyEpoch: 1, HubKeyID: hub.Public().ID, HubPublicIdentity: hub.Public(), HubKeyVersion: 1, State: "ACTIVE", Version: 1, CredentialDigest: "synthetic-credential-digest"}, OwnerKeyVersion: 1, ClientDeviceVersion: 1}
	i := &LocalTLSInstaller{StateRoot: installPrivateDir(t), WriterRoot: installPrivateDir(t), HubID: b.Control.HubID, NodeID: b.Control.NodeID, OwnerTrust: trust, NodeControlIdentity: node, CurrentBinding: func() (TLSLocalBinding, error) { return b, nil }, KnownApplicationPublicKeys: func() ([][]byte, error) {
		return [][]byte{owner.Public().SigningPublic, node.Public().SigningPublic, hub.Public().SigningPublic}, nil
	}}
	return i, owner, hub, b
}
func installTree(t *testing.T, roots ...string) string {
	t.Helper()
	var entries []string
	for index, root := range roots {
		e := filepath.WalkDir(root, func(path string, d fs.DirEntry, e error) error {
			if e != nil {
				return e
			}
			info, e := d.Info()
			if e != nil {
				return e
			}
			rel, _ := filepath.Rel(root, path)
			entry := string(rune('0'+index)) + rel + info.Mode().String()
			if info.Mode().IsRegular() {
				data, e := os.ReadFile(path)
				if e != nil {
					return e
				}
				entry += tlsHash(data)
			}
			entries = append(entries, entry)
			return nil
		})
		if e != nil {
			t.Fatal("read disposable tree")
		}
	}
	sort.Strings(entries)
	return strings.Join(entries, "\n")
}
func installDummyRequest() TLSPreparationRequest {
	hash := strings.Repeat("a", 64)
	return TLSPreparationRequest{RequestID: "synthetic-request", DNSName: "node.synthetic.invalid", HubDNSName: "hub.synthetic.invalid", HubPQOrigin: "https://hub.synthetic.invalid", ApplicationOrigin: "https://hub.synthetic.invalid", HubSPKIHash: hash, HubTrustAnchorDERHash: hash, IssuerGeneration: "synthetic-issuer-generation", IssuerSPKIHash: hash, IssuerDERHash: hash, RootDERHash: hash}
}
func TestNodeTLSInstallQuarantineEveryStageNoWrites(t *testing.T) {
	for _, kind := range []string{"node-external", "node-internal", "writer-other-node-external", "writer-internal", "writer-registry-symlink"} {
		t.Run(kind, func(t *testing.T) {
			i, _, _, _ := installSyntheticLocal(t)
			var marker string
			switch kind {
			case "node-external":
				marker = filepath.Join(i.StateRoot, "nodes", ".recovery-pending", "node-"+i.NodeID+".json")
			case "node-internal":
				marker = filepath.Join(i.StateRoot, "nodes", "node-"+i.NodeID, "recovery-pending.json")
			case "writer-other-node-external":
				marker = filepath.Join(i.WriterRoot, "nodes", ".recovery-pending", "node-unrelated.json")
			case "writer-internal":
				marker = filepath.Join(i.WriterRoot, ".writer-root-recovery-pending.json")
			case "writer-registry-symlink":
				if e := os.MkdirAll(filepath.Join(i.WriterRoot, "nodes"), 0700); e != nil {
					t.Fatal(e)
				}
				if e := os.Symlink(installPrivateDir(t), filepath.Join(i.WriterRoot, "nodes", ".recovery-pending")); e != nil {
					t.Fatal(e)
				}
			}
			if marker != "" {
				if e := os.MkdirAll(filepath.Dir(marker), 0700); e != nil {
					t.Fatal(e)
				}
				if e := os.WriteFile(marker, []byte("synthetic malformed quarantine marker"), 0600); e != nil {
					t.Fatal(e)
				}
			}
			before := installTree(t, i.StateRoot, i.WriterRoot)
			at := time.Now().UTC().Truncate(time.Second)
			if _, e := i.Prepare(installDummyRequest(), at); !errors.Is(e, ErrTLSRecoveryQuarantine) {
				t.Fatalf("prepare quarantine classification %v", e)
			}
			if _, e := i.Stage(store.NodeTLSAuthoritySnapshot{State: store.NodeTLSSigned, RowVersion: 3, ReservationVersion: 1}, nil, nil, nil, at); !errors.Is(e, ErrTLSRecoveryQuarantine) {
				t.Fatalf("stage quarantine classification %v", e)
			}
			if _, e := i.Apply(store.NodeTLSAuthoritySnapshot{State: store.NodeTLSActive, RowVersion: 5, ReservationVersion: 1}, at); !errors.Is(e, ErrTLSRecoveryQuarantine) {
				t.Fatalf("apply quarantine classification %v", e)
			}
			if _, e := i.LoadActive(at); !errors.Is(e, ErrTLSRecoveryQuarantine) {
				t.Fatalf("load quarantine classification %v", e)
			}
			if installTree(t, i.StateRoot, i.WriterRoot) != before {
				t.Fatal("quarantined installer changed disposable tree")
			}
		})
	}
}
func TestNodeTLSInstallExclusiveLocks(t *testing.T) {
	for _, kind := range []string{"agent", "writer"} {
		t.Run(kind, func(t *testing.T) {
			i, _, _, _ := installSyntheticLocal(t)
			if kind == "agent" {
				l, e := nodelock.AcquireAgent(i.StateRoot, i.NodeID)
				if e != nil {
					t.Fatal(e)
				}
				defer l.Close()
			} else {
				l, e := nodelock.AcquireWriterRoot(i.WriterRoot)
				if e != nil {
					t.Fatal(e)
				}
				defer l.Close()
			}
			if _, e := i.Prepare(installDummyRequest(), time.Now().UTC().Truncate(time.Second)); !errors.Is(e, nodelock.ErrBusy) {
				t.Fatal("installer did not exclude live writer")
			}
		})
	}
}
func TestNodeTLSInstallUnavailableIsTypedAndNoCandidate(t *testing.T) {
	if e := pqtls.Available(); e == nil {
		return
	} else if !errors.Is(e, pqtls.ErrUnavailable) {
		t.Fatal(e)
	}
	i, _, _, _ := installSyntheticLocal(t)
	if _, e := i.Prepare(installDummyRequest(), time.Now().UTC().Truncate(time.Second)); !errors.Is(e, pqtls.ErrUnavailable) {
		t.Fatalf("unavailable classification: %v", e)
	}
	if _, e := os.Lstat(i.base()); !errors.Is(e, os.ErrNotExist) {
		t.Fatal("unavailable build published TLS candidate")
	}
}

type installCA struct {
	chain, root, key []byte
	profile          pqtls.TLSIssuerProfile
	issuer           pqtls.TLSIssuer
	at               time.Time
}

func installCAFixture(t *testing.T) installCA {
	t.Helper()
	dir := installPrivateDir(t)
	executable := os.Getenv("PQTLS_TEST_OPENSSL")
	if executable == "" || !filepath.IsAbs(executable) {
		t.Fatal("native installer tests require explicit official OpenSSL fixture executable")
	}
	cli := func(args ...string) {
		t.Helper()
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		cmd := exec.CommandContext(ctx, executable, args...)
		cmd.Dir = dir
		cmd.Env = append(os.Environ(), "OPENSSL_CONF=/dev/null")
		if _, e := cmd.CombinedOutput(); e != nil {
			t.Fatal("official synthetic CA command failed; sensitive output suppressed")
		}
	}
	cli("req", "-new", "-x509", "-newkey", "ML-DSA-65", "-noenc", "-keyout", "root.key", "-out", "root.pem", "-days", "2", "-subj", "/CN=CICADA SYNTHETIC INSTALL ROOT ONLY", "-addext", "basicConstraints=critical,CA:TRUE,pathlen:1", "-addext", "keyUsage=critical,keyCertSign,cRLSign", "-addext", "subjectKeyIdentifier=hash")
	cli("req", "-new", "-newkey", "ML-DSA-65", "-noenc", "-keyout", "issuer.key", "-out", "issuer.csr", "-subj", "/CN=CICADA SYNTHETIC INSTALL ISSUER ONLY")
	if os.WriteFile(filepath.Join(dir, "issuer.ext"), []byte("basicConstraints=critical,CA:TRUE,pathlen:0\nkeyUsage=critical,keyCertSign,cRLSign\nsubjectKeyIdentifier=hash\nauthorityKeyIdentifier=keyid:always\n"), 0600) != nil {
		t.Fatal("synthetic CA extensions")
	}
	cli("x509", "-req", "-in", "issuer.csr", "-CA", "root.pem", "-CAkey", "root.key", "-CAcreateserial", "-out", "issuer.pem", "-days", "1", "-extfile", "issuer.ext")
	read := func(name string) []byte {
		t.Helper()
		b, e := os.ReadFile(filepath.Join(dir, name))
		if e != nil {
			t.Fatal("read synthetic CA material")
		}
		return b
	}
	root := read("root.pem")
	chain := append(read("issuer.pem"), root...)
	key := read("issuer.key")
	at := time.Now().UTC().Truncate(time.Second)
	issuer, profile, e := pqtls.ImportTLSIssuer(chain, key, root, "node", at)
	if e != nil {
		t.Fatal(e)
	}
	t.Cleanup(issuer.Destroy)
	t.Cleanup(func() { clear(key) })
	return installCA{chain, root, key, profile, issuer, at}
}
func installSignedFixture(t *testing.T) (*LocalTLSInstaller, store.NodeTLSAuthoritySnapshot, installCA, *e2ee.Identity, *e2ee.Identity) {
	t.Helper()
	i, owner, hub, b := installSyntheticLocal(t)
	ca := installCAFixture(t)
	r := installDummyRequest()
	r.IssuerSPKIHash = hex.EncodeToString(ca.profile.SPKIDERHash[:])
	r.IssuerDERHash = hex.EncodeToString(ca.profile.CertificateDERHash[:])
	r.RootDERHash = hex.EncodeToString(ca.profile.TrustAnchorDERHash[:])
	r.HubTrustAnchorDERHash = r.RootDERHash
	prepared, e := i.Prepare(r, ca.at)
	if e != nil {
		t.Fatal(e)
	}
	c := e2ee.OwnerTLSLeafGrantClaims{Version: 1, RequestID: r.RequestID, HubID: i.HubID, NodeID: i.NodeID, OwnerID: b.Control.OwnerID, OwnerKeyID: b.Control.OwnerKeyID, OwnerKeyVersion: b.OwnerKeyVersion, ClientDeviceID: b.Control.ClientDeviceID, ClientDeviceVersion: b.ClientDeviceVersion, OwnerBindingID: b.Control.OwnerBindingID, OwnerBindingVersion: b.Control.BindingVersion, CredentialDigest: b.Control.CredentialDigest, CredentialVersion: b.Control.NodeCredentialVersion, NodeControlKeyID: b.Control.NodeKeyID, NodeControlKeyVersion: b.Control.NodeKeyVersion, NodeControlKeyEpoch: b.Control.NodeKeyEpoch, NodeControlBindingVersion: b.Control.Version, HubControlKeyID: b.Control.HubKeyID, HubControlKeyVersion: b.Control.HubKeyVersion, CSRDERHash: prepared.CSRDERHash, SPKIDERHash: prepared.SPKIDERHash, IssuerSPKIHash: r.IssuerSPKIHash, IssuerDERHash: r.IssuerDERHash, RootDERHash: r.RootDERHash, IssuerGeneration: r.IssuerGeneration, Role: "node", DNSName: r.DNSName, Serial: "00000000000000000000000000000001", TLSEpoch: 1, NotBefore: ca.at.Format(time.RFC3339), NotAfter: ca.at.Add(time.Hour).Format(time.RFC3339), HubSPKIHash: r.HubSPKIHash, HubTrustAnchorDERHash: r.HubTrustAnchorDERHash, HubPQOrigin: r.HubPQOrigin, ApplicationOrigin: r.ApplicationOrigin, ApplicationProtocol: e2ee.NodeTLSApplicationProtocol, PQProfile: e2ee.NodeTLSPQProfile, IssuedAt: ca.at.Format(time.RFC3339), ExpiresAt: ca.at.Add(time.Hour).Format(time.RFC3339), Nonce: strings.Repeat("b", 64)}
	grant, e := e2ee.SignOwnerTLSLeafGrant(owner, c)
	if e != nil {
		t.Fatal(e)
	}
	leaf, e := ca.issuer.IssueTLSLeaf(prepared.CSRPEM, leafParameters(c), ca.at)
	if e != nil {
		t.Fatal(e)
	}
	s := store.NodeTLSAuthoritySnapshot{State: store.NodeTLSSigned, RowVersion: 3, ReservationVersion: 1, Claims: c, Grant: grant, CSRPEM: prepared.CSRPEM, IssuerChainPEM: ca.chain, TrustAnchorPEM: ca.root, LeafCertificatePEM: leaf.CertificatePEM, LeafDERHash: hex.EncodeToString(leaf.CertificateDERHash[:])}
	return i, s, ca, owner, hub
}
func installActivate(t *testing.T, i *LocalTLSInstaller, s store.NodeTLSAuthoritySnapshot, ca installCA, hub *e2ee.Identity) store.NodeTLSAuthoritySnapshot {
	t.Helper()
	ack, e := i.Stage(s, ca.chain, ca.root, ca.root, ca.at)
	if e != nil {
		t.Fatal(e)
	}
	b, e := i.CurrentBinding()
	if e != nil {
		t.Fatal(e)
	}
	claims, e := e2ee.VerifyNodeTLSInstallAck(b.Control.NodePublicIdentity, ca.at, ack)
	if e != nil {
		t.Fatal(e)
	}
	activation, e := e2ee.SignNodeTLSActivation(hub, e2ee.NodeTLSActivationClaims{Version: 1, InstallAckClaims: claims, InstallAckDigest: e2ee.NodeTLSAuthorityDigest(ack), ActivationVersion: 5, IssuedAt: ca.at.Format(time.RFC3339), ExpiresAt: s.Claims.ExpiresAt, Nonce: strings.Repeat("c", 64)})
	if e != nil {
		t.Fatal(e)
	}
	s.State = store.NodeTLSActive
	s.RowVersion = 5
	s.InstallAck = ack
	s.Activation = activation
	// This isolated fixture models a separately committed Hub row. The native
	// server gate supplies this callback from the real Store current read.
	committed := s
	i.CurrentActiveAuthority = func() (*store.NodeTLSAuthoritySnapshot, error) { copy := committed; return &copy, nil }
	return s
}
func TestNodeTLSInstallNativeFullCycleAndFloorCrash(t *testing.T) {
	if !installNativeEnabled(t) {
		return
	}
	i, s, ca, _, hub := installSignedFixture(t)
	active := installActivate(t, i, s, ca, hub)
	currentAuthority := i.CurrentActiveAuthority
	i.CurrentActiveAuthority = nil
	beforeMissing := installTree(t, i.StateRoot, i.WriterRoot)
	if _, e := i.Apply(active, ca.at); !errors.Is(e, ErrTLSCurrentAuthorityUnavailable) {
		t.Fatal("precommit signed activation without independent ACTIVE authority accepted")
	}
	if installTree(t, i.StateRoot, i.WriterRoot) != beforeMissing {
		t.Fatal("missing current authority changed floor or active files")
	}
	i.CurrentActiveAuthority = func() (*store.NodeTLSAuthoritySnapshot, error) {
		notCommitted := active
		notCommitted.State = store.NodeTLSInstalled
		return &notCommitted, nil
	}
	if _, e := i.Apply(active, ca.at); !errors.Is(e, ErrTLSInstall) {
		t.Fatal("signed activation before Store commit accepted")
	}
	if installTree(t, i.StateRoot, i.WriterRoot) != beforeMissing {
		t.Fatal("precommit signed activation changed floor or active files")
	}
	i.CurrentActiveAuthority = currentAuthority
	if _, e := os.Lstat(filepath.Join(i.base(), "active.json")); !errors.Is(e, os.ErrNotExist) {
		t.Fatal("staging activated transport")
	}
	injected := errors.New("synthetic power loss after durable floor")
	i.fault = func(point string) error {
		if point == "floor-durable" {
			return injected
		}
		return nil
	}
	if _, e := i.Apply(active, ca.at); !errors.Is(e, injected) {
		t.Fatal("floor fault not reached")
	}
	if _, e := i.LoadActive(ca.at); !errors.Is(e, ErrTLSInstall) {
		t.Fatal("partial floor/config state did not fail closed")
	}
	i.fault = nil
	wrong := active
	wrong.Activation = bytes.Clone(active.Activation)
	wrong.Activation[len(wrong.Activation)-2] ^= 1
	if _, e := i.Apply(wrong, ca.at); e == nil {
		t.Fatal("other activation repaired floor")
	}
	cfg, e := i.Apply(active, ca.at)
	if e != nil {
		t.Fatal(e)
	}
	if cfg.Identity.TLSEpoch != 1 {
		t.Fatal("wrong installed TLS epoch")
	}
	if _, e := i.LoadActive(ca.at); e != nil {
		t.Fatal(e)
	}
	for _, field := range []string{"row-version", "reservation-version", "csr", "issuer-chain", "root", "leaf"} {
		t.Run("current-"+field, func(t *testing.T) {
			i.CurrentActiveAuthority = func() (*store.NodeTLSAuthoritySnapshot, error) {
				bad := active
				switch field {
				case "row-version":
					bad.RowVersion++
				case "reservation-version":
					bad.ReservationVersion++
				case "csr":
					bad.CSRPEM = []byte("synthetic changed current CSR")
				case "issuer-chain":
					bad.IssuerChainPEM = []byte("synthetic changed current issuer")
				case "root":
					bad.TrustAnchorPEM = []byte("synthetic changed current root")
				case "leaf":
					bad.LeafCertificatePEM = []byte("synthetic changed current leaf")
				}
				return &bad, nil
			}
			if _, e := i.LoadActive(ca.at); !errors.Is(e, ErrTLSInstall) {
				t.Fatal("current ACTIVE snapshot did not match staged full tuple")
			}
			i.CurrentActiveAuthority = currentAuthority
		})
	}
	if _, e := i.Apply(active, ca.at); e != nil {
		t.Fatal("exact activation is not idempotent")
	}
	if _, e := i.Prepare(installDummyRequest(), ca.at); e == nil {
		t.Fatal("reused preparation identity")
	}
	if e := os.Chmod(cfg.PrivateKeyFile, 0644); e != nil {
		t.Fatal(e)
	}
	if _, e := i.LoadActive(ca.at); e == nil {
		t.Fatal("public private key accepted")
	}
}
func TestNodeTLSInstallNativeRejectSubstitutionAndStaleTrust(t *testing.T) {
	if !installNativeEnabled(t) {
		return
	}
	i, s, ca, owner, hub := installSignedFixture(t)
	for _, field := range []string{"leaf-hash", "issuer-spki", "application-origin", "reservation", "csr"} {
		t.Run(field, func(t *testing.T) {
			bad := s
			switch field {
			case "leaf-hash":
				bad.LeafDERHash = strings.Repeat("d", 64)
			case "issuer-spki":
				bad.Claims.IssuerSPKIHash = strings.Repeat("e", 64)
				bad.Grant, _ = e2ee.SignOwnerTLSLeafGrant(owner, bad.Claims)
			case "application-origin":
				bad.Claims.ApplicationOrigin = "https://other.synthetic.invalid"
				bad.Grant, _ = e2ee.SignOwnerTLSLeafGrant(owner, bad.Claims)
			case "reservation":
				bad.ReservationVersion = 2
			case "csr":
				bad.CSRPEM = []byte("synthetic wrong CSR")
			}
			before := installTree(t, i.StateRoot, i.WriterRoot)
			if _, e := i.Stage(bad, ca.chain, ca.root, ca.root, ca.at); e == nil {
				t.Fatal("substitution accepted")
			}
			if installTree(t, i.StateRoot, i.WriterRoot) != before {
				t.Fatal("rejected candidate changed TLS files")
			}
		})
	}
	active := installActivate(t, i, s, ca, hub)
	current := i.CurrentBinding
	i.CurrentBinding = func() (TLSLocalBinding, error) { b, e := current(); b.Control.NodeKeyEpoch++; return b, e }
	if _, e := i.Apply(active, ca.at); e == nil {
		t.Fatal("stale NodeControl binding activated")
	}
	i.CurrentBinding = current
	trust, e := i.OwnerTrust.GetNodeOwnerKeyTrustLocal(s.Claims.OwnerID, s.Claims.OwnerKeyID)
	if e != nil {
		t.Fatal(e)
	}
	if _, e = i.OwnerTrust.RevokeNodeOwnerKeyTrustLocal(trust.OwnerID, trust.KeyID, trust.Version); e != nil {
		t.Fatal(e)
	}
	if _, e = i.Apply(active, ca.at); e == nil {
		t.Fatal("revoked independent Owner trust activated")
	}
}

func installNativeEnabled(t *testing.T) bool {
	t.Helper()
	if e := pqtls.Available(); e != nil {
		if os.Getenv("PQTLS_TEST_OPENSSL") != "" || !errors.Is(e, pqtls.ErrUnavailable) {
			t.Fatal("native provider unavailable in requested native fixture run")
		}
		return false
	}
	return true
}
func TestNodeTLSInstallNativeLocalFloorAllowsHubBurnGap(t *testing.T) {
	if !installNativeEnabled(t) {
		return
	}
	i, s, ca, owner, hub := installSignedFixture(t)
	// The Hub reservation ledger independently burned epoch 1. This synthetic
	// signed candidate models its next exact approval, not a local floor rollback.
	s.Claims.ExpectedTLSEpochFloor = 1
	s.Claims.TLSEpoch = 2
	s.Claims.Serial = "00000000000000000000000000000002"
	var e error
	s.Grant, e = e2ee.SignOwnerTLSLeafGrant(owner, s.Claims)
	if e != nil {
		t.Fatal(e)
	}
	leaf, e := ca.issuer.IssueTLSLeaf(s.CSRPEM, leafParameters(s.Claims), ca.at)
	if e != nil {
		t.Fatal(e)
	}
	s.LeafCertificatePEM = leaf.CertificatePEM
	s.LeafDERHash = hex.EncodeToString(leaf.CertificateDERHash[:])
	active := installActivate(t, i, s, ca, hub)
	cfg, e := i.Apply(active, ca.at)
	if e != nil || cfg.Identity.TLSEpoch != 2 {
		t.Fatal("Hub burned reservation gap blocked exact new activation")
	}
	if _, e = i.LoadActive(ca.at); e != nil {
		t.Fatal(e)
	}
}
