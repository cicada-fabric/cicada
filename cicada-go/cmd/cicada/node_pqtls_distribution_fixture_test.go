//go:build linux && amd64 && cgo && cicada_pqtls

package main

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/cicada-ai/cicada/internal/e2ee"
	"github.com/cicada-ai/cicada/internal/fabric"
	"github.com/cicada-ai/cicada/internal/nodekeys"
	"github.com/cicada-ai/cicada/internal/nodetransport"
	"github.com/cicada-ai/cicada/internal/nodewire"
	"github.com/cicada-ai/cicada/internal/pqtls"
	"github.com/cicada-ai/cicada/internal/store"
)

// Distribution-only synthetic setup. The old sealed fixture already registers
// actual signed OwnerDevice and OwnerLink grants. Upgrade its legacy bearer
// bindings through the current application-key API before issuing TLS leaves.
// No production artifact, Control instance, Guard or enrollment endpoint changes.
type distributionTLSFixture struct {
	root, hubState string
	hubConfig      nodetransport.Config
	nodes          map[string]runtimeStartupFixture
}

func distributionActiveConfigPath(f runtimeStartupFixture) string {
	bucket := sha256.Sum256([]byte(f.Binding.HubID + "\x00" + f.Binding.NodeID))
	return filepath.Join(f.StateRoot, ".node-tls", hex.EncodeToString(bucket[:]), "active.json")
}

func distributionCurrentTLSFixture(t *testing.T, sealed *machineSealedReceiveFixture, address, applicationOrigin string) distributionTLSFixture {
	t.Helper()
	base := os.Getenv("PQTLS_TEST_ARTIFACT_DIR")
	if base == "" || os.Getenv("PQTLS_TEST_OPENSSL") == "" {
		t.Fatal("private evidence root and official OpenSSL fixture executable required")
	}
	root, err := os.MkdirTemp(base, "synthetic-current-distribution-")
	if err != nil {
		t.Fatal("private host-visible synthetic fixture root")
	}
	t.Cleanup(func() {
		if err := os.RemoveAll(root); err != nil {
			t.Error("private current distribution fixture cleanup failed")
		}
	})
	hubState := filepath.Join(root, "hub-state")
	if err := os.MkdirAll(filepath.Join(hubState, "e2ee"), 0700); err != nil {
		t.Fatal("private synthetic Hub layout")
	}
	if err := sealed.store.Close(); err != nil {
		t.Fatal("close synthetic seed Store")
	}
	data, err := os.ReadFile(sealed.databasePath)
	if err != nil {
		t.Fatal("read closed synthetic seed Store")
	}
	database := filepath.Join(hubState, "cicada.sqlite3")
	runtimeStartupWrite(t, database, data)
	db, err := store.New(database)
	if err != nil {
		t.Fatal("open isolated synthetic Hub Store")
	}
	defer db.Close()
	hubID, err := db.GetClientHubID()
	if err != nil {
		t.Fatal("actual synthetic Hub ID")
	}
	hub, err := e2ee.NewIdentity()
	if err != nil {
		t.Fatal("synthetic HubControl identity")
	}
	secret, err := hub.MarshalBinary()
	if err != nil {
		t.Fatal("synthetic HubControl serialization")
	}
	runtimeStartupWrite(t, filepath.Join(hubState, "e2ee", "identity.json"), secret)
	runtimeStartupWrite(t, filepath.Join(hubState, "e2ee", "node-control-identity.json"), secret)
	clear(secret)
	chain, rootPEM, issuerSecret, at := runtimeStartupCA(t, root)
	defer clear(issuerSecret)
	issuer, issuerProfile, err := pqtls.ImportTLSIssuer(chain, issuerSecret, rootPEM, "node", at)
	if err != nil {
		t.Fatal("official synthetic Node TLS issuer")
	}
	defer issuer.Destroy()
	hubIssuer, _, err := pqtls.ImportTLSIssuer(chain, issuerSecret, rootPEM, "hub", at)
	if err != nil {
		t.Fatal("official synthetic Hub TLS issuer")
	}
	defer hubIssuer.Destroy()
	hubTLSKey, hubCSR, err := pqtls.GenerateTLSCSR(pqtls.TLSCSRParameters{Role: "hub", DNSName: "hub.synthetic.invalid"})
	if err != nil {
		t.Fatal("independent synthetic Hub TLS CSR")
	}
	defer hubTLSKey.Destroy()
	hubParameters := pqtls.TLSLeafParameters{TLSCSRParameters: hubCSR.Parameters, NotBefore: at, NotAfter: at.Add(time.Hour), ExpectedSPKIHash: hubCSR.SPKIDERHash}
	hubParameters.Serial[15] = 99
	hubLeaf, err := hubIssuer.IssueTLSLeaf(hubCSR.CSRPEM, hubParameters, at)
	if err != nil {
		t.Fatal("official synthetic Hub TLS leaf")
	}
	secret, err = hubTLSKey.ExportPEM()
	if err != nil {
		t.Fatal("synthetic Hub TLS private fixture write")
	}
	runtimeStartupWrite(t, filepath.Join(root, "hub.key"), secret)
	clear(secret)
	runtimeStartupWrite(t, filepath.Join(root, "hub-chain.pem"), append(append([]byte(nil), hubLeaf.CertificatePEM...), chain...))
	runtimeStartupWrite(t, filepath.Join(root, "root.pem"), rootPEM)
	result := distributionTLSFixture{root: root, hubState: hubState, nodes: make(map[string]runtimeStartupFixture), hubConfig: nodetransport.Config{Version: 1, Role: "hub", Listen: address, CertificateFile: filepath.Join(root, "hub-chain.pem"), PrivateKeyFile: filepath.Join(root, "hub.key"), TrustFile: filepath.Join(root, "root.pem"), Identity: nodetransport.Identity{Kind: "hub", HubID: hubID, DNSName: "hub.synthetic.invalid"}}}
	type nodeSetup struct {
		id, token, dns string
		owner          *e2ee.Identity
		node           *e2ee.Identity
		binding        *store.NodeControlKeyBinding
		device         *store.ClientDevice
		ownerKey       *store.OwnerApprovalKey
	}
	setups := []nodeSetup{{id: sealed.sourceNodeID, token: sealed.sourceToken, dns: "node-a.synthetic.invalid", owner: sealed.sourceOwnerIdentity}, {id: sealed.targetNodeID, token: sealed.targetToken, dns: "node-b.synthetic.invalid", owner: sealed.targetOwnerIdentity}}
	for index := range setups {
		n := &setups[index]
		old, err := db.CurrentNodeTransportBinding(n.id)
		if err != nil {
			t.Fatal("current legacy synthetic Owner binding")
		}
		n.device, err = db.GetClientDevice(old.OwnerID, "client_"+n.id)
		if err != nil {
			t.Fatal("registered synthetic OwnerDevice grant")
		}
		n.ownerKey, err = db.GetOwnerApprovalKey(old.OwnerID, old.OwnerKeyID)
		if err != nil {
			t.Fatal("current synthetic Owner approval key")
		}
		n.node, err = e2ee.NewIdentity()
		if err != nil {
			t.Fatal("synthetic NodeControl identity")
		}
		nonce := make([]byte, 32)
		if _, err := rand.Read(nonce); err != nil {
			t.Fatal("synthetic pairing nonce")
		}
		transcript, err := nodewire.PairingProofTranscript(nodewire.PairingProofContext{HubID: hubID, NodeID: n.id, RequestNonce: nonce, CredentialDigest: fabric.HashSessionCredential(n.token), NodePublicIdentity: n.node.Public(), HubPublicIdentity: hub.Public(), HubKeyVersion: 1})
		if err != nil {
			t.Fatal("actual synthetic pairing transcript")
		}
		proof, err := e2ee.Seal(n.node, hub.Public(), transcript, nodewire.PairingProofAAD(), 1)
		if err != nil {
			t.Fatal("actual synthetic NIST possession proof")
		}
		opened, sequence, err := e2ee.Open(hub, n.node.Public(), proof, nodewire.PairingProofAAD())
		if err != nil || sequence != 1 || string(opened) != string(transcript) {
			t.Fatal("synthetic pairing possession proof invalid")
		}
		clear(opened)
		code := nodewire.RecoveryDigest([]byte("SYNTHETIC distribution upgrade " + n.id))
		candidate, err := db.StartNodeControlKeyRequest(store.NodeControlKeyRequestInput{Mode: store.NodeControlPairingUpgrade, NodeID: n.id, NodeName: n.id, CredentialDigest: fabric.HashSessionCredential(n.token), CodeDigest: code, NodePublicIdentity: n.node.Public(), NodeFingerprint: nodewire.IdentityFingerprint(n.node.Public()), ProofPacket: proof, HubPublicIdentity: hub.Public(), HubKeyVersion: 1, HubFingerprint: nodewire.IdentityFingerprint(hub.Public()), TargetBindingID: old.BindingID, ExpiresAt: time.Now().Add(10 * time.Minute)})
		if err != nil {
			t.Fatal("actual synthetic application-key upgrade reservation")
		}
		n.binding, err = db.ConfirmNodeControlKeyRequest(old.OwnerID, n.device.DeviceID, code, candidate.Version, candidate.CandidateDigest, candidate.HubNodeControlKeyID, candidate.HubNodeControlFingerprint)
		if err != nil {
			t.Fatal("actual current synthetic OwnerDevice confirmation")
		}
	}
	// Complete fixture-owned inventory, retained Owner and endpoint keys plus
	// both registered devices/current NodeControls and HubControl; never a bundle
	// supplied inventory or a fabricated CSR/application-key comparison.
	known := [][]byte{sealed.sourceOwnerIdentity.Public().SigningPublic, sealed.targetOwnerIdentity.Public().SigningPublic, sealed.sourceKey.Public().SigningPublic, sealed.targetKey.Public().SigningPublic, hub.Public().SigningPublic}
	for _, n := range setups {
		known = append(known, n.node.Public().SigningPublic, n.device.Public.SigningPublic)
	}
	hash := func(b [32]byte) string { return hex.EncodeToString(b[:]) }
	_, port, err := net.SplitHostPort(address)
	if err != nil {
		t.Fatal("synthetic native physical address")
	}
	pqOrigin := "https://hub.synthetic.invalid:" + port
	for _, n := range setups {
		trust, err := nodekeys.OpenCryptoState(machineNodeStateDir(sealed.stateDir, n.id))
		if err != nil {
			t.Fatal("actual retained synthetic Owner/Endpoint trust")
		}
		installer := &nodetransport.LocalTLSInstaller{StateRoot: sealed.stateDir, WriterRoot: sealed.stateDir, HubID: hubID, NodeID: n.id, OwnerTrust: trust, NodeControlIdentity: n.node, CurrentBinding: func() (nodetransport.TLSLocalBinding, error) {
			b, e := db.NodeControlKeyForCredential(fabric.HashSessionCredential(n.token), n.id)
			if e != nil {
				return nodetransport.TLSLocalBinding{}, e
			}
			return nodetransport.TLSLocalBinding{Control: *b, OwnerKeyVersion: uint64(n.ownerKey.Version), ClientDeviceVersion: uint64(n.device.Version)}, nil
		}, KnownApplicationPublicKeys: func() ([][]byte, error) { return known, nil }, CurrentActiveAuthority: func() (*store.NodeTLSAuthoritySnapshot, error) {
			b, e := db.CurrentNodeTransportBinding(n.id)
			if e != nil {
				return nil, e
			}
			return b.TLSAuthority, nil
		}}
		request := nodetransport.TLSPreparationRequest{RequestID: "synthetic-distribution-tls-" + n.id, DNSName: n.dns, HubDNSName: "hub.synthetic.invalid", HubPQOrigin: pqOrigin, ApplicationOrigin: applicationOrigin, HubSPKIHash: hash(hubCSR.SPKIDERHash), HubTrustAnchorDERHash: hash(issuerProfile.TrustAnchorDERHash), IssuerGeneration: "synthetic-distribution-issuer", IssuerSPKIHash: hash(issuerProfile.SPKIDERHash), IssuerDERHash: hash(issuerProfile.CertificateDERHash), RootDERHash: hash(issuerProfile.TrustAnchorDERHash)}
		prepared, err := installer.Prepare(request, at)
		if err != nil {
			trust.Close()
			t.Fatal("actual synthetic TLS Prepare")
		}
		reservation, err := db.ReserveNodeTLSCandidate(store.NodeTLSCandidateInput{RequestID: request.RequestID, NodeID: n.id, CredentialDigest: fabric.HashSessionCredential(n.token), CSRPEM: prepared.CSRPEM, IssuerChainPEM: chain, TrustAnchorPEM: rootPEM, Parameters: pqtls.TLSCSRParameters{Role: "node", DNSName: n.dns}, Issuer: issuerProfile, IssuerGeneration: request.IssuerGeneration, NotBefore: at, NotAfter: at.Add(time.Hour), HubSPKIHash: request.HubSPKIHash, HubTrustAnchorDERHash: request.HubTrustAnchorDERHash, HubPQOrigin: request.HubPQOrigin, ApplicationOrigin: applicationOrigin, GrantIssuedAt: at, GrantExpiresAt: at.Add(time.Hour), GrantNonce: nodewire.RecoveryDigest([]byte("SYNTHETIC TLS grant " + n.id))})
		if err != nil {
			trust.Close()
			t.Fatal("actual synthetic TLS authority reservation")
		}
		grant, err := e2ee.SignOwnerTLSLeafGrant(n.owner, reservation.Claims)
		if err != nil {
			trust.Close()
			t.Fatal("actual synthetic OwnerTLS signature")
		}
		action := store.NodeTLSAuthorityActionInput{RequestID: request.RequestID, NodeID: n.id, CredentialDigest: fabric.HashSessionCredential(n.token), ExpectedVersion: reservation.RowVersion}
		signed, err := db.IssueNodeTLSLeaf(store.NodeTLSLeafIssueInput{NodeTLSAuthorityActionInput: action, Grant: grant}, issuer)
		if err != nil {
			trust.Close()
			t.Fatal("actual official synthetic TLS issuance")
		}
		ack, err := installer.Stage(*signed, chain, rootPEM, rootPEM, time.Now().UTC().Truncate(time.Second))
		if err != nil {
			trust.Close()
			t.Fatal("actual synthetic TLS Stage ACK")
		}
		action.ExpectedVersion = signed.RowVersion
		installed, err := db.RecordNodeTLSInstallAck(store.NodeTLSInstallAckInput{NodeTLSAuthorityActionInput: action, InstallAck: ack})
		if err != nil {
			trust.Close()
			t.Fatal("actual synthetic committed install ACK")
		}
		action.ExpectedVersion = installed.RowVersion
		claims, err := db.PrepareNodeTLSActivation(action, nodewire.RecoveryDigest([]byte("SYNTHETIC activation "+n.id)))
		if err != nil {
			trust.Close()
			t.Fatal("actual synthetic activation claims")
		}
		activation, err := e2ee.SignNodeTLSActivation(hub, claims)
		if err != nil {
			trust.Close()
			t.Fatal("actual synthetic HubControl activation signature")
		}
		active, err := db.ActivateNodeTLSGrant(store.NodeTLSActivationInput{NodeTLSAuthorityActionInput: action, Activation: activation})
		if err != nil {
			trust.Close()
			t.Fatal("actual synthetic committed ACTIVE")
		}
		config, err := installer.Apply(*active, time.Now().UTC().Truncate(time.Second))
		if err != nil || trust.Close() != nil {
			t.Fatal("actual synthetic checked TLS Apply")
		}
		f := runtimeStartupFixture{ActiveVersion: active.RowVersion, DBPath: database, RequestID: request.RequestID, Token: n.token, StateRoot: sealed.stateDir, WriterRoot: sealed.stateDir, NodeConfig: *config, Binding: n.binding, Node: n.node, Hub: hub}
		runtimeStartupPersistApplicationState(t, f)
		result.nodes[n.id] = f
		result.hubConfig.Peers = append(result.hubConfig.Peers, nodetransport.Approval{Identity: config.Identity, PinKind: "spki-sha256", PinSHA256: active.Claims.SPKIDERHash, OwnerID: n.binding.OwnerID, OwnerKeyID: n.binding.OwnerKeyID, BindingID: n.binding.OwnerBindingID, BindingVersion: int64(n.binding.BindingVersion), CredentialVersion: int64(n.binding.NodeCredentialVersion)})
	}
	return result
}
