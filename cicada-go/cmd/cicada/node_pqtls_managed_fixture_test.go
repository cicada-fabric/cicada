//go:build linux && amd64 && cgo && cicada_pqtls

package main

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/cicada-ai/cicada/internal/control"
	"github.com/cicada-ai/cicada/internal/e2ee"
	"github.com/cicada-ai/cicada/internal/fabric"
	"github.com/cicada-ai/cicada/internal/nodekeys"
	"github.com/cicada-ai/cicada/internal/nodetransport"
	"github.com/cicada-ai/cicada/internal/pqtls"
	"github.com/cicada-ai/cicada/internal/store"
)

// Test-only material: the Store and all application identities belong to the
// caller's existing fixture. TLS keys are independently generated synthetic keys.
type productManagedPQMaterial struct {
	chain, root, issuerKey []byte
	issuerProfile          pqtls.TLSIssuerProfile
	hubConfig              nodetransport.Config
	hubSPKI                string
	at, notAfter           time.Time
}

func productManagedPQCA(t *testing.T, dir, hubID, pqOrigin, logicalOrigin string, validity time.Duration) productManagedPQMaterial {
	t.Helper()
	if err := os.MkdirAll(dir, 0700); err != nil {
		t.Fatal(err)
	}
	chain, root, key, at := runtimeStartupCA(t, dir)
	issuer, profile, err := pqtls.ImportTLSIssuer(chain, key, root, "node", at)
	if err != nil {
		t.Fatal(err)
	}
	issuer.Destroy()
	hubIssuer, _, err := pqtls.ImportTLSIssuer(chain, key, root, "hub", at)
	if err != nil {
		t.Fatal(err)
	}
	defer hubIssuer.Destroy()
	tlsKey, csr, err := pqtls.GenerateTLSCSR(pqtls.TLSCSRParameters{Role: "hub", DNSName: "hub.synthetic.invalid"})
	if err != nil {
		t.Fatal(err)
	}
	defer tlsKey.Destroy()
	params := pqtls.TLSLeafParameters{TLSCSRParameters: csr.Parameters, NotBefore: at, NotAfter: at.Add(validity), ExpectedSPKIHash: csr.SPKIDERHash}
	params.Serial[15] = 99
	leaf, err := hubIssuer.IssueTLSLeaf(csr.CSRPEM, params, at)
	if err != nil {
		t.Fatal(err)
	}
	secret, err := tlsKey.ExportPEM()
	if err != nil {
		t.Fatal(err)
	}
	runtimeStartupWrite(t, filepath.Join(dir, "hub.key"), secret)
	clear(secret)
	runtimeStartupWrite(t, filepath.Join(dir, "hub-chain.pem"), append(append([]byte(nil), leaf.CertificatePEM...), chain...))
	runtimeStartupWrite(t, filepath.Join(dir, "root.pem"), root)
	t.Cleanup(func() { clear(key) })
	return productManagedPQMaterial{chain: chain, root: root, issuerKey: key, issuerProfile: profile, notAfter: at.Add(validity), hubSPKI: hex.EncodeToString(csr.SPKIDERHash[:]), at: at, hubConfig: nodetransport.Config{Version: 1, Role: "hub", CertificateFile: filepath.Join(dir, "hub-chain.pem"), PrivateKeyFile: filepath.Join(dir, "hub.key"), TrustFile: filepath.Join(dir, "root.pem"), Identity: nodetransport.Identity{Kind: "hub", HubID: hubID, DNSName: "hub.synthetic.invalid"}}}
}

// Upgrade the existing Node credential through actual Owner confirmation. No
// bearer, Owner key or Client device is replaced; the resulting binding version
// is read back and subsequently used by both activation and current authority.
func productManagedPQEnroll(t *testing.T, db *store.Store, nodeID, token, ownerID, deviceID string, node, hub *e2ee.Identity) *store.NodeControlKeyBinding {
	t.Helper()
	current, err := db.CurrentNodeTransportBinding(nodeID)
	if err != nil {
		t.Fatal(err)
	}
	nonce := make([]byte, 32)
	if _, err = rand.Read(nonce); err != nil {
		t.Fatal(err)
	}
	hubPublic := control.NodeControlHubIdentity{HubID: current.HubID, PublicIdentity: hub.Public(), KeyVersion: 1}
	proof, err := productNodePairingProof(node, hubPublic, nodeID, fabric.HashSessionCredential(token), nonce)
	if err != nil {
		t.Fatal(err)
	}
	code := sha256.Sum256(append([]byte("synthetic managed TLS upgrade "+nodeID), nonce...))
	digest := hex.EncodeToString(code[:])
	candidate, err := db.StartNodeControlKeyRequest(store.NodeControlKeyRequestInput{Mode: store.NodeControlPairingUpgrade, NodeID: nodeID, NodeName: nodeID, CredentialDigest: fabric.HashSessionCredential(token), CodeDigest: digest, NodePublicIdentity: node.Public(), NodeFingerprint: productNodeFingerprint(node.Public()), ProofPacket: proof, HubPublicIdentity: hub.Public(), HubKeyVersion: 1, HubFingerprint: productNodeFingerprint(hub.Public()), TargetBindingID: current.BindingID, ExpiresAt: time.Now().Add(10 * time.Minute)})
	if err != nil {
		t.Fatal(err)
	}
	binding, err := db.ConfirmNodeControlKeyRequest(ownerID, deviceID, digest, candidate.Version, candidate.CandidateDigest, candidate.HubNodeControlKeyID, candidate.HubNodeControlFingerprint)
	if err != nil {
		t.Fatal(err)
	}
	return binding
}

type productManagedPQNodeInput struct {
	DB                                                             *store.Store
	Owner, Node                                                    *e2ee.Identity
	Binding                                                        *store.NodeControlKeyBinding
	Token, StateRoot, WriterRoot, PQOrigin, LogicalOrigin, DNSName string
	// Control-backed fixtures supply its actual activation method. Fabric-only
	// fixtures sign with the same Hub application identity used for enrollment.
	Activate            func(store.NodeTLSAuthorityActionInput, string) (*store.NodeTLSAuthoritySnapshot, error)
	Hub                 *e2ee.Identity
	PreserveApplication bool
}

func productManagedPQActivate(t *testing.T, material productManagedPQMaterial, in productManagedPQNodeInput, notAfter time.Time) runtimeStartupFixture {
	t.Helper()
	b := in.Binding
	owner, err := in.DB.GetOwnerApprovalKey(b.OwnerID, b.OwnerKeyID)
	if err != nil {
		t.Fatal("managed TLS owner record failed")
	}
	device, err := in.DB.GetClientDevice(b.OwnerID, b.ClientDeviceID)
	if err != nil {
		t.Fatal("managed TLS device record failed")
	}
	for _, dir := range []string{in.StateRoot, in.WriterRoot, machineNodeStateDir(in.StateRoot, b.NodeID)} {
		if err = os.MkdirAll(dir, 0700); err != nil {
			t.Fatal("managed TLS local directories failed")
		}
	}
	trust, err := nodekeys.OpenCryptoState(machineNodeStateDir(in.StateRoot, b.NodeID))
	if err != nil {
		t.Fatal("managed TLS local trust open failed")
	}
	defer trust.Close()
	fingerprint, err := nodekeys.PeerKeyFingerprint(in.Owner.Public())
	if err != nil {
		t.Fatal("managed TLS owner fingerprint failed")
	}
	if _, err = trust.TrustOwnerApprovalKeyLocal(b.OwnerID, b.OwnerKeyID, in.Owner.Public(), fingerprint); err != nil {
		t.Fatal("managed TLS owner trust failed")
	}
	// Finish the owned trust setup before opening the same stable read-only
	// inventory used by production Runtime admission.
	if err := trust.Close(); err != nil {
		t.Fatal("managed TLS local trust close failed")
	}
	reader, err := nodekeys.OpenExistingCryptoStateReadOnly(machineNodeStateDir(in.StateRoot, b.NodeID))
	if err != nil {
		t.Fatal("managed TLS retained trust reader failed")
	}
	defer reader.Close()
	installer := &nodetransport.LocalTLSInstaller{StateRoot: in.StateRoot, WriterRoot: in.WriterRoot, HubID: b.HubID, NodeID: b.NodeID, OwnerTrust: reader.State, NodeControlIdentity: in.Node, CurrentBinding: func() (nodetransport.TLSLocalBinding, error) {
		current, e := in.DB.NodeControlKeyForCredential(fabric.HashSessionCredential(in.Token), b.NodeID)
		if e != nil {
			return nodetransport.TLSLocalBinding{}, e
		}
		return nodetransport.TLSLocalBinding{Control: *current, OwnerKeyVersion: uint64(owner.Version), ClientDeviceVersion: uint64(device.Version)}, nil
	}, KnownApplicationPublicKeys: func() ([][]byte, error) {
		retained, err := reader.RetainedSigningPublicKeys()
		if err != nil {
			return nil, err
		}
		baseDigest := sha256.Sum256([]byte(b.HubID + "\x00" + b.NodeID))
		preparedDir := filepath.Join(in.StateRoot, ".node-tls", hex.EncodeToString(baseDigest[:]), "prepared")
		// First Prepare asks for known keys before creating its prepared directory.
		// Only proven absence is empty; existing inventory must pass the same
		// production reader, including ownership, symlink and record validation.
		if _, err := os.Lstat(preparedDir); err == nil {
			old, err := nodetransport.ReadRetainedTLSPreparationSigningPublicKeys(in.StateRoot, in.WriterRoot, b.HubID, b.NodeID)
			if err != nil {
				return nil, err
			}
			retained = append(retained, old...)
		} else if !errors.Is(err, os.ErrNotExist) {
			return nil, err
		}
		retained = append(retained, in.Owner.Public().SigningPublic, in.Node.Public().SigningPublic, b.HubPublicIdentity.SigningPublic, device.Public.SigningPublic)
		if reader.CheckStable() != nil {
			return nil, nodekeys.ErrRuntimeTrustUnavailable
		}
		return retained, nil
	}, CurrentActiveAuthority: func() (*store.NodeTLSAuthoritySnapshot, error) {
		current, e := in.DB.CurrentNodeTransportBinding(b.NodeID)
		if e != nil {
			return nil, e
		}
		return current.TLSAuthority, nil
	}}
	hash := func(v [32]byte) string { return hex.EncodeToString(v[:]) }
	request := nodetransport.TLSPreparationRequest{RequestID: "synthetic-managed-tls-" + b.NodeID, DNSName: in.DNSName, HubDNSName: material.hubConfig.Identity.DNSName, HubPQOrigin: in.PQOrigin, ApplicationOrigin: in.LogicalOrigin, HubSPKIHash: material.hubSPKI, HubTrustAnchorDERHash: hash(material.issuerProfile.TrustAnchorDERHash), IssuerGeneration: "synthetic-managed-issuer", IssuerSPKIHash: hash(material.issuerProfile.SPKIDERHash), IssuerDERHash: hash(material.issuerProfile.CertificateDERHash), RootDERHash: hash(material.issuerProfile.TrustAnchorDERHash)}
	at := time.Now().UTC().Truncate(time.Second)
	prepared, err := installer.Prepare(request, at)
	if err != nil {
		t.Fatal("managed TLS prepare failed")
	}
	grantNonceBytes := make([]byte, 32)
	if _, err := rand.Read(grantNonceBytes); err != nil {
		t.Fatal("managed TLS grant nonce failed")
	}
	grantNonce := hex.EncodeToString(grantNonceBytes)
	clear(grantNonceBytes)
	activationNonceBytes := make([]byte, 32)
	if _, err := rand.Read(activationNonceBytes); err != nil {
		t.Fatal("managed TLS activation nonce failed")
	}
	activationNonce := hex.EncodeToString(activationNonceBytes)
	clear(activationNonceBytes)
	reservation, err := in.DB.ReserveNodeTLSCandidate(store.NodeTLSCandidateInput{RequestID: request.RequestID, NodeID: b.NodeID, CredentialDigest: fabric.HashSessionCredential(in.Token), CSRPEM: prepared.CSRPEM, IssuerChainPEM: material.chain, TrustAnchorPEM: material.root, Parameters: pqtls.TLSCSRParameters{Role: "node", DNSName: in.DNSName}, Issuer: material.issuerProfile, IssuerGeneration: request.IssuerGeneration, NotBefore: at, NotAfter: notAfter, HubSPKIHash: request.HubSPKIHash, HubTrustAnchorDERHash: request.HubTrustAnchorDERHash, HubPQOrigin: in.PQOrigin, ApplicationOrigin: in.LogicalOrigin, GrantIssuedAt: at, GrantExpiresAt: notAfter, GrantNonce: grantNonce})
	if err != nil {
		switch {
		case errors.Is(err, store.ErrNodeTLSAuthorityDenied):
			t.Fatal("managed TLS reserve failed: AUTHORITY_DENIED")
		case errors.Is(err, store.ErrNodeTLSAuthorityConflict):
			t.Fatal("managed TLS reserve failed: AUTHORITY_CONFLICT")
		case errors.Is(err, store.ErrNodeTLSAuthorityCapacity):
			t.Fatal("managed TLS reserve failed: AUTHORITY_CAPACITY")
		default:
			t.Fatal("managed TLS reserve failed: UNCLASSIFIED")
		}
	}
	grant, err := e2ee.SignOwnerTLSLeafGrant(in.Owner, reservation.Claims)
	if err != nil {
		t.Fatal("managed TLS owner grant failed")
	}
	issuer, _, err := pqtls.ImportTLSIssuer(material.chain, material.issuerKey, material.root, "node", at)
	if err != nil {
		t.Fatal("managed TLS issuer import failed")
	}
	defer issuer.Destroy()
	action := store.NodeTLSAuthorityActionInput{RequestID: request.RequestID, NodeID: b.NodeID, CredentialDigest: fabric.HashSessionCredential(in.Token), ExpectedVersion: reservation.RowVersion}
	signed, err := in.DB.IssueNodeTLSLeaf(store.NodeTLSLeafIssueInput{NodeTLSAuthorityActionInput: action, Grant: grant}, issuer)
	if err != nil {
		t.Fatal("managed TLS issue failed")
	}
	// Proof consumption uses the real current wall clock, not the earlier
	// preparation timestamp. Certificate/grant expiry remains unchanged.
	stageAt := time.Now().UTC().Truncate(time.Second)
	ack, err := installer.Stage(*signed, material.chain, material.root, material.root, stageAt)
	if err != nil {
		t.Fatal("managed TLS stage failed")
	}
	action.ExpectedVersion = signed.RowVersion
	installed, err := in.DB.RecordNodeTLSInstallAck(store.NodeTLSInstallAckInput{NodeTLSAuthorityActionInput: action, InstallAck: ack})
	if err != nil {
		t.Fatal("managed TLS install acknowledgement failed")
	}
	action.ExpectedVersion = installed.RowVersion
	var active *store.NodeTLSAuthoritySnapshot
	if in.Activate != nil {
		active, err = in.Activate(action, activationNonce)
	} else {
		claims, e := in.DB.PrepareNodeTLSActivation(action, activationNonce)
		if e != nil {
			t.Fatal("managed TLS activation preparation failed")
		}
		proof, e := e2ee.SignNodeTLSActivation(in.Hub, claims)
		if e != nil {
			t.Fatal("managed TLS activation signature failed")
		}
		active, err = in.DB.ActivateNodeTLSGrant(store.NodeTLSActivationInput{NodeTLSAuthorityActionInput: action, Activation: proof})
	}
	if err != nil {
		t.Fatal("managed TLS activation failed")
	}
	// Store activation is issued at its own current UTC second; applying at
	// the pre-Prepare time can incorrectly classify that proof as future-issued.
	applyAt := time.Now().UTC().Truncate(time.Second)
	config, err := installer.Apply(*active, applyAt)
	if err != nil {
		switch {
		case errors.Is(err, nodetransport.ErrTLSCurrentAuthorityUnavailable):
			t.Fatal("managed TLS apply failed: CURRENT_AUTHORITY_UNAVAILABLE")
		case errors.Is(err, nodetransport.ErrTLSInstall):
			t.Fatal("managed TLS apply failed: TLS_INSTALL")
		default:
			t.Fatal("managed TLS apply failed: UNCLASSIFIED")
		}
	}
	f := runtimeStartupFixture{ActiveVersion: active.RowVersion, RequestID: request.RequestID, Token: in.Token, StateRoot: in.StateRoot, WriterRoot: in.WriterRoot, NodeConfig: *config, HubConfig: material.hubConfig, Binding: b, Node: in.Node, Hub: in.Hub}
	if !in.PreserveApplication {
		runtimeStartupPersistApplicationState(t, f)
	}
	return f
}

func productManagedPQPath(f runtimeStartupFixture) string {
	return filepath.Clean(filepath.Join(filepath.Dir(f.NodeConfig.PrivateKeyFile), "..", "..", "active.json"))
}

func productManagedPQApproval(t *testing.T, db *store.Store, f runtimeStartupFixture) nodetransport.Approval {
	t.Helper()
	current, err := db.CurrentNodeTransportBinding(f.Binding.NodeID)
	if err != nil {
		t.Fatal(err)
	}
	return nodetransport.Approval{Identity: f.NodeConfig.Identity, PinKind: "spki-sha256", PinSHA256: current.TLSAuthority.Claims.SPKIDERHash, OwnerID: current.OwnerID, OwnerKeyID: current.OwnerKeyID, BindingID: current.BindingID, BindingVersion: current.BindingVersion, CredentialVersion: current.CredentialVersion}
}

// Owner TLS grants require a qualified DNS name. runtimeStartupDNS resolves
// only this synthetic name to the owned loopback listener in each test process.
func productManagedPQOrigin(t *testing.T, address string) string {
	t.Helper()
	_, port, err := net.SplitHostPort(address)
	if err != nil {
		t.Fatal("managed TLS listener address invalid")
	}
	return "https://" + net.JoinHostPort("hub.synthetic.invalid", port)
}

// This valid same-issuer certificate is deliberately never granted/activated.
// Its rejection must therefore exercise current peer authority, not wrong CA.
func productManagedPQUnactivatedLeaf(t *testing.T, material productManagedPQMaterial, dir string) (string, string) {
	t.Helper()
	at := time.Now().UTC().Truncate(time.Second)
	issuer, _, err := pqtls.ImportTLSIssuer(material.chain, material.issuerKey, material.root, "node", at)
	if err != nil {
		t.Fatal("stale TLS issuer import failed")
	}
	defer issuer.Destroy()
	key, csr, err := pqtls.GenerateTLSCSR(pqtls.TLSCSRParameters{Role: "node", DNSName: "old-node-a.synthetic.invalid"})
	if err != nil {
		t.Fatal("stale TLS CSR failed")
	}
	defer key.Destroy()
	params := pqtls.TLSLeafParameters{TLSCSRParameters: csr.Parameters, NotBefore: at, NotAfter: material.notAfter, ExpectedSPKIHash: csr.SPKIDERHash}
	params.Serial[14] = 1
	leaf, err := issuer.IssueTLSLeaf(csr.CSRPEM, params, at)
	if err != nil {
		t.Fatal("stale TLS leaf issue failed")
	}
	secret, err := key.ExportPEM()
	if err != nil {
		t.Fatal("stale TLS key export failed")
	}
	defer clear(secret)
	keyPath, leafPath := filepath.Join(dir, "unactivated-node.key"), filepath.Join(dir, "unactivated-node.pem")
	runtimeStartupWrite(t, keyPath, secret)
	runtimeStartupWrite(t, leafPath, append(append([]byte(nil), leaf.CertificatePEM...), material.chain...))
	return leafPath, keyPath
}
