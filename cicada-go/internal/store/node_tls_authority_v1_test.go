package store

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"math"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/cicada-ai/cicada/internal/e2ee"
	"github.com/cicada-ai/cicada/internal/pqtls"
)

func nodeTLSTestHash(label string) string {
	return e2ee.NodeTLSAuthorityDigest([]byte("CICADA SYNTHETIC TLS AUTHORITY TEST ONLY: " + label))
}
func nodeTLSTestIdentity(t *testing.T) *e2ee.Identity {
	t.Helper()
	i, err := e2ee.NewIdentity()
	if err != nil {
		t.Fatal(err)
	}
	return i
}
func nodeTLSTestClaims(t *testing.T) (e2ee.OwnerTLSLeafGrantClaims, *e2ee.Identity, *e2ee.Identity, *e2ee.Identity, time.Time) {
	t.Helper()
	owner, node, hub := nodeTLSTestIdentity(t), nodeTLSTestIdentity(t), nodeTLSTestIdentity(t)
	at := nodeTLSNow()
	c := e2ee.OwnerTLSLeafGrantClaims{Version: 1, RequestID: "synthetic_tls_request", HubID: "synthetic_hub", NodeID: "synthetic_node", OwnerID: "owner_a", OwnerKeyID: owner.Public().ID, OwnerKeyVersion: 1, ClientDeviceID: "phone_a", ClientDeviceVersion: 1, OwnerBindingID: "synthetic_binding", OwnerBindingVersion: 1, CredentialDigest: nodeBindingTestCredentialDigest("tls-e2ee-domain"), CredentialVersion: 1,
		NodeControlKeyID: node.Public().ID, NodeControlKeyVersion: 1, NodeControlKeyEpoch: 1, NodeControlBindingVersion: 1, HubControlKeyID: hub.Public().ID, HubControlKeyVersion: 1,
		CSRDERHash: nodeTLSTestHash("csr"), SPKIDERHash: nodeTLSTestHash("spki"), IssuerSPKIHash: nodeTLSTestHash("issuer-spki"), IssuerDERHash: nodeTLSTestHash("issuer-der"), RootDERHash: nodeTLSTestHash("root"), IssuerGeneration: "synthetic_issuer_v1", Role: "node", DNSName: "node.synthetic.invalid", Serial: strings.Repeat("0", 31) + "1", TLSEpoch: 1,
		NotBefore: nodeTLSStamp(at.Add(-time.Minute)), NotAfter: nodeTLSStamp(at.Add(2 * time.Hour)), HubSPKIHash: nodeTLSTestHash("hub-spki"), HubTrustAnchorDERHash: nodeTLSTestHash("hub-root"), HubPQOrigin: "https://hub.synthetic.invalid:7443", ApplicationOrigin: "http://127.0.0.1:8080", ApplicationProtocol: e2ee.NodeTLSApplicationProtocol, PQProfile: e2ee.NodeTLSPQProfile, IssuedAt: nodeTLSStamp(at.Add(-time.Minute)), ExpiresAt: nodeTLSStamp(at.Add(time.Hour)), Nonce: nodeTLSTestHash("grant-nonce")}
	return c, owner, node, hub, at
}

func TestNodeTLSAuthorityDedicatedDomainsAndExactClaims(t *testing.T) {
	c, owner, node, hub, at := nodeTLSTestClaims(t)
	wire, err := e2ee.SignOwnerTLSLeafGrant(owner, c)
	if err != nil {
		t.Fatal(err)
	}
	verified, err := e2ee.VerifyOwnerTLSLeafGrant(owner.Public(), at, wire)
	if err != nil || verified != c {
		t.Fatal("exact human grant did not verify")
	}
	if _, err = e2ee.VerifyOwnerTLSLeafGrant(node.Public(), at, wire); err == nil {
		t.Fatal("Node bearer identity became human approval")
	}
	ack := e2ee.NodeTLSInstallAckClaims{Version: 1, GrantClaims: c, GrantDigest: e2ee.NodeTLSAuthorityDigest(wire), ReservationVersion: 1, LeafDERHash: nodeTLSTestHash("leaf"), IssuedAt: nodeTLSStamp(at), ExpiresAt: c.ExpiresAt, Nonce: nodeTLSTestHash("ack-nonce")}
	ackWire, err := e2ee.SignNodeTLSInstallAck(node, ack)
	if err != nil {
		t.Fatal(err)
	}
	if got, err := e2ee.VerifyNodeTLSInstallAck(node.Public(), at, ackWire); err != nil || got != ack {
		t.Fatal("dedicated install ACK did not verify")
	}
	activation := e2ee.NodeTLSActivationClaims{Version: 1, InstallAckClaims: ack, InstallAckDigest: e2ee.NodeTLSAuthorityDigest(ackWire), ActivationVersion: 5, IssuedAt: nodeTLSStamp(at), ExpiresAt: c.ExpiresAt, Nonce: nodeTLSTestHash("activation-nonce")}
	activeWire, err := e2ee.SignNodeTLSActivation(hub, activation)
	if err != nil {
		t.Fatal(err)
	}
	if got, err := e2ee.VerifyNodeTLSActivation(hub.Public(), at, activeWire); err != nil || got != activation {
		t.Fatal("dedicated activation did not verify")
	}
	for name, proof := range map[string][]byte{"install": ackWire, "activation": activeWire} {
		t.Run(name+"_is_not_owner_approval", func(t *testing.T) {
			if _, err := e2ee.VerifyOwnerTLSLeafGrant(owner.Public(), at, proof); err == nil {
				t.Fatal("foreign purpose accepted")
			}
		})
	}
	if _, err = e2ee.VerifyNodeTLSInstallAck(node.Public(), at, wire); err == nil {
		t.Fatal("Owner grant became install evidence")
	}
	if _, err = e2ee.VerifyNodeTLSActivation(hub.Public(), at, ackWire); err == nil {
		t.Fatal("Node ACK became Hub activation")
	}
	var unsigned e2ee.OwnerTLSLeafGrant
	if err = json.Unmarshal(wire, &unsigned); err != nil {
		t.Fatal(err)
	}
	mutations := map[string]func(*e2ee.OwnerTLSLeafGrantClaims){
		"hub": func(v *e2ee.OwnerTLSLeafGrantClaims) { v.HubID = "foreign_hub" }, "node": func(v *e2ee.OwnerTLSLeafGrantClaims) { v.NodeID = "foreign_node" }, "owner": func(v *e2ee.OwnerTLSLeafGrantClaims) { v.OwnerID = "foreign_owner" },
		"csr": func(v *e2ee.OwnerTLSLeafGrantClaims) { v.CSRDERHash = nodeTLSTestHash("other-csr") }, "spki": func(v *e2ee.OwnerTLSLeafGrantClaims) { v.SPKIDERHash = nodeTLSTestHash("other-spki") }, "issuer": func(v *e2ee.OwnerTLSLeafGrantClaims) { v.IssuerSPKIHash = nodeTLSTestHash("other-issuer") },
		"serial": func(v *e2ee.OwnerTLSLeafGrantClaims) { v.Serial = strings.Repeat("0", 31) + "2" }, "binding": func(v *e2ee.OwnerTLSLeafGrantClaims) { v.OwnerBindingVersion++ }, "device": func(v *e2ee.OwnerTLSLeafGrantClaims) { v.ClientDeviceVersion++ },
		"credential": func(v *e2ee.OwnerTLSLeafGrantClaims) { v.CredentialDigest = nodeBindingTestCredentialDigest("changed") }, "node_control": func(v *e2ee.OwnerTLSLeafGrantClaims) { v.NodeControlKeyEpoch++ }, "hub_control": func(v *e2ee.OwnerTLSLeafGrantClaims) { v.HubControlKeyVersion++ },
		"logical_origin": func(v *e2ee.OwnerTLSLeafGrantClaims) { v.ApplicationOrigin = "https://foreign.synthetic.invalid" }, "pq_origin": func(v *e2ee.OwnerTLSLeafGrantClaims) { v.HubPQOrigin = "https://foreign.synthetic.invalid" }, "time": func(v *e2ee.OwnerTLSLeafGrantClaims) { v.NotAfter = nodeTLSStamp(at.Add(3 * time.Hour)) },
	}
	for name, mutate := range mutations {
		t.Run(name, func(t *testing.T) {
			changed := unsigned
			mutate(&changed.Claims)
			bad, _ := json.Marshal(changed)
			if _, err := e2ee.VerifyOwnerTLSLeafGrant(owner.Public(), at, bad); err == nil {
				t.Fatal("unsigned exact-claim substitution accepted")
			}
		})
	}
	for _, bad := range [][]byte{append(bytes.Clone(wire), '\n'), append(bytes.Clone(wire), []byte("{}")...), bytes.Replace(wire, []byte(`"version":1`), []byte(`"version":1,"version":1`), 1), bytes.Replace(wire, []byte(`"claims":{`), []byte(`"extra":true,"claims":{`), 1)} {
		if _, err := e2ee.VerifyOwnerTLSLeafGrant(owner.Public(), at, bad); err == nil {
			t.Fatal("noncanonical, duplicate, unknown or trailing JSON accepted")
		}
	}
	if _, err := e2ee.VerifyOwnerTLSLeafGrant(owner.Public(), at.Add(2*time.Hour), wire); err == nil {
		t.Fatal("expired grant accepted")
	}
	if _, err := e2ee.VerifyOwnerTLSLeafGrant(owner.Public(), at.Add(-2*time.Minute), wire); err == nil {
		t.Fatal("future grant accepted")
	}
	for _, mutate := range []func(*e2ee.OwnerTLSLeafGrantClaims){func(v *e2ee.OwnerTLSLeafGrantClaims) { v.HubPQOrigin += "?" }, func(v *e2ee.OwnerTLSLeafGrantClaims) { v.ApplicationOrigin += "?" }, func(v *e2ee.OwnerTLSLeafGrantClaims) { v.ApplicationOrigin = "http://foreign.synthetic.invalid" }, func(v *e2ee.OwnerTLSLeafGrantClaims) { v.DNSName = "127.0.0.1" }, func(v *e2ee.OwnerTLSLeafGrantClaims) { v.Nonce = strings.Repeat("0", 64) }, func(v *e2ee.OwnerTLSLeafGrantClaims) { v.TLSEpoch = math.MaxInt64 + 1 }} {
		bad := c
		mutate(&bad)
		if _, err := e2ee.SignOwnerTLSLeafGrant(owner, bad); err == nil {
			t.Fatal("malformed approval claims signed")
		}
	}
	ack.Nonce = strings.Repeat("0", 64)
	if _, err := e2ee.SignNodeTLSInstallAck(node, ack); err == nil {
		t.Fatal("zero install nonce signed")
	}
}

func TestNodeTLSAuthoritySchemaAndUnavailableFailClosed(t *testing.T) {
	s, _, _, device := newClientDeviceFixture(t)
	node, hub := nodeTLSTestIdentity(t), nodeTLSTestIdentity(t)
	digest := nodeBindingTestCredentialDigest("tls-unavailable")
	candidate := startStoreNodeControlRequest(t, s, "tls-unavailable-node", digest, NodeControlPairingInitial, "", node, hub, "tls-unavailable")
	confirmStoreNodeControlRequest(t, s, device, candidate, "tls-unavailable")
	var version int
	if err := s.db.QueryRow(`SELECT max(version) FROM schema_migrations_v2 WHERE state='applied'`).Scan(&version); err != nil || version != 56 {
		t.Fatal("TLS schema migration not installed")
	}
	if _, err := s.CurrentNodeTransportBinding(candidate.NodeID); err != nil {
		t.Fatal("optional ordinary transport binding broken without TLS authority")
	}
	if available := pqtls.Available(); available != nil {
		if !errors.Is(available, pqtls.ErrUnavailable) {
			t.Fatal("native absence is not typed unavailable")
		}
		if _, err := s.ReserveNodeTLSCandidate(NodeTLSCandidateInput{RequestID: "unavailable_request", NodeID: candidate.NodeID, CredentialDigest: digest, Parameters: pqtls.TLSCSRParameters{Role: "node", DNSName: "node.synthetic.invalid"}, Issuer: pqtls.TLSIssuerProfile{Role: "node"}, CSRPEM: []byte("CICADA SYNTHETIC INVALID CSR")}); !errors.Is(err, pqtls.ErrUnavailable) {
			t.Fatal("default implementation pretended CSR verification succeeded")
		}
		var count int
		if err := s.db.QueryRow(`SELECT count(*) FROM node_tls_authority_v1`).Scan(&count); err != nil || count != 0 {
			t.Fatal("unavailable native verification changed reservation state")
		}
	}
}

func TestNodeTLSAuthorityPermanentInventoryAndOverflow(t *testing.T) {
	s, owner, _, _ := newClientDeviceFixture(t)
	tx, err := s.db.Begin()
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback()
	keys, err := nodeTLSApplicationKeysTx(tx, true)
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, key := range keys {
		if bytes.Equal(key, owner.Public().SigningPublic) {
			found = true
		}
	}
	if !found {
		t.Fatal("Owner application signing public omitted")
	}
	if _, err = tx.Exec(`UPDATE owner_approval_keys_v2 SET state='REVOKED' WHERE owner_id='owner_a'`); err != nil {
		t.Fatal(err)
	}
	keys, err = nodeTLSApplicationKeysTx(tx, false)
	if err != nil {
		t.Fatal(err)
	}
	found = false
	for _, key := range keys {
		if bytes.Equal(key, owner.Public().SigningPublic) {
			found = true
		}
	}
	if !found {
		t.Fatal("revoked application key omitted")
	}
	if _, err = nodeTLSNextSerial(strings.Repeat("f", 32)); !errors.Is(err, ErrNodeTLSAuthorityCapacity) {
		t.Fatal("128-bit serial wrapped")
	}
	if serial, err := nodeTLSNextSerial(strings.Repeat("0", 30) + "ff"); err != nil || serial != strings.Repeat("0", 29)+"100" {
		t.Fatal("serial high watermark did not carry")
	}
	if _, err = tx.Exec(`INSERT INTO node_tls_epoch_floors_v1(hub_id,node_id,floor) VALUES('synthetic_hub','synthetic_node',5)`); err != nil {
		t.Fatal(err)
	}
	if _, err = tx.Exec(`UPDATE node_tls_epoch_floors_v1 SET floor=4 WHERE hub_id='synthetic_hub'`); err == nil {
		t.Fatal("epoch rollback SQL accepted")
	}
	if _, err = tx.Exec(`DELETE FROM node_tls_epoch_floors_v1 WHERE hub_id='synthetic_hub'`); err == nil {
		t.Fatal("permanent epoch watermark deletion accepted")
	}
	if _, err = tx.Exec(`DELETE FROM node_tls_application_keys_v1`); err == nil {
		t.Fatal("retained application public deletion accepted")
	}
	for i := 0; i < NodeTLSAuthorityApplicationKeyCapacity; i++ {
		key := make([]byte, 1952)
		key[0], key[1], key[2] = byte(i), byte(i>>8), 0x7f
		if _, err = tx.Exec(`INSERT INTO node_tls_application_keys_v1(signing_public) VALUES(?)`, key); err != nil {
			t.Fatal(err)
		}
	}
	if _, err = nodeTLSApplicationKeysTx(tx, false); !errors.Is(err, ErrNodeTLSAuthorityCapacity) {
		t.Fatal("over-cap retained inventory accepted")
	}
}

type nodeTLSNativeFixture struct {
	s                *Store
	owner, node, hub *e2ee.Identity
	device           *ClientDevice
	binding          *NodeControlKeyBinding
	digest           string
	input            NodeTLSCandidateInput
	issuer           pqtls.TLSIssuer
	dir              string
}

func nodeTLSNativeCLI(t *testing.T, dir string, args ...string) {
	t.Helper()
	binary := os.Getenv("PQTLS_TEST_OPENSSL")
	if binary == "" || !filepath.IsAbs(binary) {
		t.Fatal("native authority test requires pinned absolute PQTLS_TEST_OPENSSL")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, binary, args...)
	cmd.Dir = dir
	cmd.Env = append(os.Environ(), "OPENSSL_CONF=/dev/null")
	if _, err := cmd.CombinedOutput(); err != nil {
		t.Fatal("official synthetic TLS authority fixture command failed; output suppressed")
	}
}

func newNodeTLSNativeFixture(t *testing.T) nodeTLSNativeFixture {
	t.Helper()
	s, owner, _, device := newClientDeviceFixture(t)
	node, hub := nodeTLSTestIdentity(t), nodeTLSTestIdentity(t)
	digest := nodeBindingTestCredentialDigest("tls-native-closure")
	candidate := startStoreNodeControlRequest(t, s, "tls-native-node", digest, NodeControlPairingInitial, "", node, hub, "tls-native")
	binding := confirmStoreNodeControlRequest(t, s, device, candidate, "tls-native")
	dir := t.TempDir()
	if err := os.Chmod(dir, 0700); err != nil {
		t.Fatal(err)
	}
	nodeTLSNativeCLI(t, dir, "req", "-new", "-x509", "-newkey", "ML-DSA-65", "-noenc", "-keyout", "root.key", "-out", "root.pem", "-days", "2", "-subj", "/CN=CICADA SYNTHETIC ROOT ONLY", "-addext", "basicConstraints=critical,CA:TRUE,pathlen:1", "-addext", "keyUsage=critical,keyCertSign,cRLSign", "-addext", "subjectKeyIdentifier=hash")
	nodeTLSNativeCLI(t, dir, "req", "-new", "-newkey", "ML-DSA-65", "-noenc", "-keyout", "issuer.key", "-out", "issuer.csr", "-subj", "/CN=CICADA SYNTHETIC ISSUER ONLY")
	if err := os.WriteFile(filepath.Join(dir, "issuer.ext"), []byte("basicConstraints=critical,CA:TRUE,pathlen:0\nkeyUsage=critical,keyCertSign,cRLSign\nsubjectKeyIdentifier=hash\nauthorityKeyIdentifier=keyid:always\n"), 0600); err != nil {
		t.Fatal(err)
	}
	nodeTLSNativeCLI(t, dir, "x509", "-req", "-in", "issuer.csr", "-CA", "root.pem", "-CAkey", "root.key", "-CAcreateserial", "-out", "issuer.pem", "-days", "1", "-extfile", "issuer.ext")
	read := func(name string) []byte {
		data, err := os.ReadFile(filepath.Join(dir, name))
		if err != nil {
			t.Fatal("read synthetic TLS fixture")
		}
		return data
	}
	root, chain, key := read("root.pem"), read("issuer.pem"), read("issuer.key")
	chain = append(chain, root...)
	defer clear(key)
	at := nodeTLSNow()
	issuer, profile, err := pqtls.ImportTLSIssuer(chain, key, root, "node", at)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(issuer.Destroy)
	tlsKey, csr, err := pqtls.GenerateTLSCSR(pqtls.TLSCSRParameters{Role: "node", DNSName: "node.synthetic.invalid"})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(tlsKey.Destroy)
	input := NodeTLSCandidateInput{RequestID: "synthetic_native_tls_request", NodeID: binding.NodeID, CredentialDigest: digest, CSRPEM: csr.CSRPEM, IssuerChainPEM: chain, TrustAnchorPEM: root, Parameters: csr.Parameters, Issuer: profile, IssuerGeneration: "synthetic_issuer_v1", NotBefore: at, NotAfter: at.Add(time.Hour), HubSPKIHash: nodeTLSTestHash("hub-leaf-spki"), HubTrustAnchorDERHash: nodeTLSTestHash("hub-leaf-trust"), HubPQOrigin: "https://hub.synthetic.invalid:7443", ApplicationOrigin: "http://127.0.0.1:8080", GrantIssuedAt: at, GrantExpiresAt: at.Add(time.Hour), GrantNonce: nodeTLSTestHash("native-grant-nonce")}
	return nodeTLSNativeFixture{s: s, owner: owner, node: node, hub: hub, device: device, binding: binding, digest: digest, input: input, issuer: issuer, dir: dir}
}

func nodeTLSNativeRequired(t *testing.T) bool {
	t.Helper()
	if err := pqtls.Available(); err != nil {
		if os.Getenv("PQTLS_TEST_OPENSSL") != "" {
			t.Fatal("native authority gate requested but native adapter unavailable")
		}
		if !errors.Is(err, pqtls.ErrUnavailable) {
			t.Fatal(err)
		}
		t.Log("NOT_RUN native authority branch: typed native unavailable; default rejection covered separately")
		return false
	}
	return true
}

func nodeTLSActivateFixture(t *testing.T, f nodeTLSNativeFixture, r *NodeTLSAuthoritySnapshot) *NodeTLSAuthoritySnapshot {
	t.Helper()
	grant, err := e2ee.SignOwnerTLSLeafGrant(f.owner, r.Claims)
	if err != nil {
		t.Fatal(err)
	}
	action := NodeTLSAuthorityActionInput{RequestID: r.Claims.RequestID, NodeID: r.Claims.NodeID, CredentialDigest: f.digest, ExpectedVersion: r.RowVersion}
	signed, err := f.s.IssueNodeTLSLeaf(NodeTLSLeafIssueInput{NodeTLSAuthorityActionInput: action, Grant: grant}, f.issuer)
	if err != nil {
		t.Fatal(err)
	}
	if signed.State != NodeTLSSigned || len(signed.LeafCertificatePEM) == 0 {
		t.Fatal("actual C issuance not persisted")
	}
	if b, err := f.s.CurrentNodeTransportBinding(r.Claims.NodeID); err != nil || (b.TLSAuthority != nil && b.TLSAuthority.Claims.RequestID == r.Claims.RequestID) {
		t.Fatal("uninstalled new leaf became current authority")
	}
	ackClaims := e2ee.NodeTLSInstallAckClaims{Version: 1, GrantClaims: signed.Claims, GrantDigest: e2ee.NodeTLSAuthorityDigest(grant), ReservationVersion: signed.ReservationVersion, LeafDERHash: signed.LeafDERHash, IssuedAt: nodeTLSStamp(nodeTLSNow()), ExpiresAt: signed.Claims.ExpiresAt, Nonce: nodeTLSTestHash("ack-" + r.Claims.RequestID)}
	ack, err := e2ee.SignNodeTLSInstallAck(f.node, ackClaims)
	if err != nil {
		t.Fatal(err)
	}
	action.ExpectedVersion = signed.RowVersion
	installed, err := f.s.RecordNodeTLSInstallAck(NodeTLSInstallAckInput{NodeTLSAuthorityActionInput: action, InstallAck: ack})
	if err != nil {
		t.Fatal(err)
	}
	action.ExpectedVersion = installed.RowVersion
	activationClaims, err := f.s.PrepareNodeTLSActivation(action, nodeTLSTestHash("activation-"+r.Claims.RequestID))
	if err != nil {
		t.Fatal(err)
	}
	activation, err := e2ee.SignNodeTLSActivation(f.hub, activationClaims)
	if err != nil {
		t.Fatal(err)
	}
	active, err := f.s.ActivateNodeTLSGrant(NodeTLSActivationInput{NodeTLSAuthorityActionInput: action, Activation: activation})
	if err != nil {
		t.Fatal(err)
	}
	if active.State != NodeTLSActive || active.RowVersion != activationClaims.ActivationVersion {
		t.Fatal("signed install/activation did not become single active")
	}
	current, err := f.s.CurrentNodeTransportBinding(r.Claims.NodeID)
	if err != nil || current.TLSAuthority == nil || current.TLSAuthority.LeafDERHash != active.LeafDERHash || current.TLSAuthority.Claims != r.Claims {
		t.Fatal("exact current TLS authority unavailable")
	}
	return active
}

func TestNodeTLSAuthorityNativeClosureExactDERAndRotation(t *testing.T) {
	if !nodeTLSNativeRequired(t) {
		return
	}
	f := newNodeTLSNativeFixture(t)
	r, err := f.s.ReserveNodeTLSCandidate(f.input)
	if err != nil {
		t.Fatal(err)
	}
	if retry, err := f.s.ReserveNodeTLSCandidate(f.input); err != nil || retry.Claims != r.Claims || retry.RowVersion != r.RowVersion {
		t.Fatal("exact reservation retry changed candidate")
	}
	bad := f.input
	bad.NotAfter = bad.NotAfter.Add(time.Second)
	if _, err := f.s.ReserveNodeTLSCandidate(bad); !errors.Is(err, ErrNodeTLSAuthorityConflict) {
		t.Fatal("different candidate request replay accepted")
	}
	active := nodeTLSActivateFixture(t, f, r)
	grant := active.Grant
	retry, err := f.s.IssueNodeTLSLeaf(NodeTLSLeafIssueInput{NodeTLSAuthorityActionInput: NodeTLSAuthorityActionInput{RequestID: r.Claims.RequestID, NodeID: r.Claims.NodeID, CredentialDigest: f.digest, ExpectedVersion: 1}, Grant: grant}, f.issuer)
	if err != nil || !bytes.Equal(retry.LeafCertificatePEM, active.LeafCertificatePEM) {
		t.Fatal("issuance retry did not return exact persisted DER")
	}
	params, err := NodeTLSLeafParameters(r.Claims)
	if err != nil {
		t.Fatal(err)
	}
	resigned, err := f.issuer.IssueTLSLeaf(r.CSRPEM, params, nodeTLSNow())
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(resigned.CertificatePEM, active.LeafCertificatePEM) {
		if _, err := f.s.CommitNodeTLSLeaf(NodeTLSAuthorityActionInput{RequestID: r.Claims.RequestID, NodeID: r.Claims.NodeID, CredentialDigest: f.digest, ExpectedVersion: active.RowVersion}, resigned.CertificatePEM); !errors.Is(err, ErrNodeTLSAuthorityConflict) {
			t.Fatal("same serial differently signed DER replaced persisted leaf")
		}
	}
	next := f.input
	next.RequestID = "synthetic_rotation_request"
	next.ExpectedTLSEpochFloor = 1
	next.GrantNonce = nodeTLSTestHash("rotation-grant-nonce")
	r2, err := f.s.ReserveNodeTLSCandidate(next)
	if err != nil {
		t.Fatal(err)
	}
	if current, err := f.s.CurrentNodeTransportBinding(r.Claims.NodeID); err != nil || current.TLSAuthority == nil || current.TLSAuthority.LeafDERHash != active.LeafDERHash || current.TLSAuthority.Claims != active.Claims {
		t.Fatal("higher reservation displaced exact prior ACTIVE before activation")
	}
	active2 := nodeTLSActivateFixture(t, f, r2)
	if active2.Claims.TLSEpoch != 2 || active2.Claims.Serial == active.Claims.Serial {
		t.Fatal("rotation reused serial or epoch")
	}
	old, err := f.s.GetNodeTLSAuthorityReservationLocal(r.Claims.RequestID)
	if err != nil || old.State != NodeTLSRevoked {
		t.Fatal("activation did not revoke prior epoch")
	}
	if err := f.s.RevokeNodeTLSGrantLocal(active2.Claims.RequestID, active2.RowVersion); err != nil {
		t.Fatal(err)
	}
	if current, err := f.s.CurrentNodeTransportBinding(r.Claims.NodeID); err != nil || current.TLSAuthority != nil {
		t.Fatal("revoked grant remained current")
	}
}

func TestNodeTLSAuthorityNativeIssuerScopeAndProofForgery(t *testing.T) {
	if !nodeTLSNativeRequired(t) {
		return
	}
	f := newNodeTLSNativeFixture(t)
	bad := f.input
	bad.Issuer.SPKIDERHash[0] ^= 1
	if _, err := f.s.ReserveNodeTLSCandidate(bad); !errors.Is(err, ErrNodeTLSAuthorityDenied) {
		t.Fatal("caller issuer profile changed actual serial namespace")
	}
	r, err := f.s.ReserveNodeTLSCandidate(f.input)
	if err != nil {
		t.Fatal(err)
	}
	grant, err := e2ee.SignOwnerTLSLeafGrant(f.owner, r.Claims)
	if err != nil {
		t.Fatal(err)
	}
	action := NodeTLSAuthorityActionInput{RequestID: r.Claims.RequestID, NodeID: r.Claims.NodeID, CredentialDigest: f.digest, ExpectedVersion: r.RowVersion}
	foreign := newNodeTLSNativeFixture(t)
	if _, err := f.s.IssueNodeTLSLeaf(NodeTLSLeafIssueInput{NodeTLSAuthorityActionInput: action, Grant: grant}, foreign.issuer); !errors.Is(err, ErrNodeTLSAuthorityDenied) {
		t.Fatal("unapproved opaque issuer was allowed to sign")
	}
	if unchanged, err := f.s.GetNodeTLSAuthorityReservationLocal(r.Claims.RequestID); err != nil || unchanged.State != NodeTLSReserved || unchanged.RowVersion != 1 {
		t.Fatal("wrong opaque issuer consumed reservation before exact signing approval")
	}
	outside := foreign.input
	outside.RequestID = "synthetic_outside_actual_issuer_window"
	outside.NotBefore = outside.Issuer.VerifiedNotAfter.Add(-30 * time.Minute)
	outside.NotAfter = outside.Issuer.VerifiedNotAfter.Add(time.Second)
	outside.Issuer.VerifiedNotAfter = outside.NotAfter
	outside.GrantNonce = nodeTLSTestHash("outside-actual-issuer-window")
	outsideReservation, err := foreign.s.ReserveNodeTLSCandidate(outside)
	if err != nil {
		t.Fatal(err)
	}
	outsideGrant, err := e2ee.SignOwnerTLSLeafGrant(foreign.owner, outsideReservation.Claims)
	if err != nil {
		t.Fatal(err)
	}
	outsideAction := NodeTLSAuthorityActionInput{RequestID: outside.RequestID, NodeID: outside.NodeID, CredentialDigest: foreign.digest, ExpectedVersion: 1}
	if _, err := foreign.s.IssueNodeTLSLeaf(NodeTLSLeafIssueInput{NodeTLSAuthorityActionInput: outsideAction, Grant: outsideGrant}, foreign.issuer); !errors.Is(err, ErrNodeTLSAuthorityDenied) {
		t.Fatal("caller profile widened actual opaque issuer validity")
	}
	if unchanged, err := foreign.s.GetNodeTLSAuthorityReservationLocal(outside.RequestID); err != nil || unchanged.State != NodeTLSReserved || unchanged.RowVersion != 1 {
		t.Fatal("invalid actual issuer window consumed reservation before signing")
	}
	signed, err := f.s.IssueNodeTLSLeaf(NodeTLSLeafIssueInput{NodeTLSAuthorityActionInput: action, Grant: grant}, f.issuer)
	if err != nil {
		t.Fatal(err)
	}
	action.ExpectedVersion = signed.RowVersion
	if _, err := f.s.RecordNodeTLSInstallAck(NodeTLSInstallAckInput{NodeTLSAuthorityActionInput: action, InstallAck: []byte(`{"installed":true}`)}); !errors.Is(err, ErrNodeTLSAuthorityDenied) {
		t.Fatal("unsigned install assertion accepted")
	}
	ackClaims := e2ee.NodeTLSInstallAckClaims{Version: 1, GrantClaims: signed.Claims, GrantDigest: e2ee.NodeTLSAuthorityDigest(grant), ReservationVersion: signed.ReservationVersion, LeafDERHash: signed.LeafDERHash, IssuedAt: nodeTLSStamp(nodeTLSNow()), ExpiresAt: signed.Claims.ExpiresAt, Nonce: signed.Claims.Nonce}
	ack, err := e2ee.SignNodeTLSInstallAck(f.node, ackClaims)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.s.RecordNodeTLSInstallAck(NodeTLSInstallAckInput{NodeTLSAuthorityActionInput: action, InstallAck: ack}); !errors.Is(err, ErrNodeTLSAuthorityConflict) {
		t.Fatal("grant nonce reused as install nonce")
	}
	ackClaims.Nonce = nodeTLSTestHash("issuer-scope-install")
	forgedClaims := ackClaims
	forgedClaims.GrantClaims.NodeControlKeyID = foreign.node.Public().ID
	forged, err := e2ee.SignNodeTLSInstallAck(foreign.node, forgedClaims)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.s.RecordNodeTLSInstallAck(NodeTLSInstallAckInput{NodeTLSAuthorityActionInput: action, InstallAck: forged}); !errors.Is(err, ErrNodeTLSAuthorityDenied) {
		t.Fatal("foreign NodeControl install assertion accepted")
	}
	ack, err = e2ee.SignNodeTLSInstallAck(f.node, ackClaims)
	if err != nil {
		t.Fatal(err)
	}
	installed, err := f.s.RecordNodeTLSInstallAck(NodeTLSInstallAckInput{NodeTLSAuthorityActionInput: action, InstallAck: ack})
	if err != nil {
		t.Fatal(err)
	}
	action.ExpectedVersion = installed.RowVersion
	activationClaims, err := f.s.PrepareNodeTLSActivation(action, nodeTLSTestHash("issuer-scope-activation"))
	if err != nil {
		t.Fatal(err)
	}
	activationClaims.InstallAckClaims.GrantClaims.HubControlKeyID = foreign.hub.Public().ID
	activation, err := e2ee.SignNodeTLSActivation(foreign.hub, activationClaims)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.s.ActivateNodeTLSGrant(NodeTLSActivationInput{NodeTLSAuthorityActionInput: action, Activation: activation}); !errors.Is(err, ErrNodeTLSAuthorityDenied) {
		t.Fatal("foreign HubControl activation accepted")
	}
	if err := f.s.RevokeNodeTLSGrantLocal(r.Claims.RequestID, installed.RowVersion); err != nil {
		t.Fatal(err)
	}
	// A renewed CA certificate retains the actual signing-SPKI namespace.
	nodeTLSNativeCLI(t, f.dir, "x509", "-req", "-in", "issuer.csr", "-CA", "root.pem", "-CAkey", "root.key", "-set_serial", "991", "-out", "renewed-issuer.pem", "-days", "1", "-extfile", "issuer.ext")
	issuerPEM, err := os.ReadFile(filepath.Join(f.dir, "renewed-issuer.pem"))
	if err != nil {
		t.Fatal("read synthetic renewed issuer")
	}
	key, err := os.ReadFile(filepath.Join(f.dir, "issuer.key"))
	if err != nil {
		t.Fatal("read synthetic issuer key")
	}
	defer clear(key)
	chain := append(issuerPEM, f.input.TrustAnchorPEM...)
	at := nodeTLSNow()
	issuer, profile, err := pqtls.ImportTLSIssuer(chain, key, f.input.TrustAnchorPEM, "node", at)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(issuer.Destroy)
	if profile.SPKIDERHash != f.input.Issuer.SPKIDERHash || profile.CertificateDERHash == f.input.Issuer.CertificateDERHash {
		t.Fatal("synthetic issuer renewal did not retain key and replace certificate")
	}
	next := f.input
	next.RequestID, next.GrantNonce = "synthetic_same_ca_key_renewed_cert", nodeTLSTestHash("renewed-ca-grant")
	next.ExpectedTLSEpochFloor = 1
	next.Issuer, next.IssuerChainPEM = profile, chain
	next.NotBefore, next.NotAfter = at, at.Add(time.Hour)
	next.GrantIssuedAt, next.GrantExpiresAt = at, at.Add(time.Hour)
	r2, err := f.s.ReserveNodeTLSCandidate(next)
	if err != nil {
		t.Fatal(err)
	}
	if r2.Claims.Serial == r.Claims.Serial || r2.Claims.IssuerSPKIHash != r.Claims.IssuerSPKIHash || r2.Claims.TLSEpoch != 2 {
		t.Fatal("same CA key certificate renewal reset permanent serial or Node epoch")
	}
	f.issuer = issuer
	nodeTLSActivateFixture(t, f, r2)
}

func TestNodeTLSAuthorityNativeBurnNonceAndCAS(t *testing.T) {
	if !nodeTLSNativeRequired(t) {
		return
	}
	f := newNodeTLSNativeFixture(t)
	var wg sync.WaitGroup
	outcomes := make(chan error, 2)
	for i := 0; i < 2; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			input := f.input
			if i == 1 {
				input.RequestID = "synthetic_racing_request"
				input.GrantNonce = nodeTLSTestHash("race-nonce")
			}
			_, err := f.s.ReserveNodeTLSCandidate(input)
			outcomes <- err
		}(i)
	}
	wg.Wait()
	close(outcomes)
	success, conflict := 0, 0
	for err := range outcomes {
		if err == nil {
			success++
		} else if errors.Is(err, ErrNodeTLSAuthorityConflict) {
			conflict++
		} else {
			t.Fatal(err)
		}
	}
	if success != 1 || conflict != 1 {
		t.Fatal("same expected epoch had multiple reservation winners")
	}
	var requestID string
	if err := f.s.db.QueryRow(`SELECT request_id FROM node_tls_authority_v1`).Scan(&requestID); err != nil {
		t.Fatal(err)
	}
	r, err := f.s.GetNodeTLSAuthorityReservationLocal(requestID)
	if err != nil {
		t.Fatal(err)
	}
	grant, err := e2ee.SignOwnerTLSLeafGrant(f.owner, r.Claims)
	if err != nil {
		t.Fatal(err)
	}
	action := NodeTLSAuthorityActionInput{RequestID: requestID, NodeID: r.Claims.NodeID, CredentialDigest: f.digest, ExpectedVersion: r.RowVersion}
	if _, err := f.s.BeginNodeTLSLeafIssue(NodeTLSLeafIssueInput{NodeTLSAuthorityActionInput: action, Grant: nil}); !errors.Is(err, ErrNodeTLSAuthorityDenied) {
		t.Fatal("CSR without exact human TLS grant authorized issuance")
	}
	if _, err := f.s.BeginNodeTLSLeafIssue(NodeTLSLeafIssueInput{NodeTLSAuthorityActionInput: action, Grant: grant}); err != nil {
		t.Fatal(err)
	}
	if _, err := f.s.IssueNodeTLSLeaf(NodeTLSLeafIssueInput{NodeTLSAuthorityActionInput: action, Grant: grant}, f.issuer); !errors.Is(err, ErrNodeTLSAuthorityUncertain) {
		t.Fatal("interrupted signing reservation was re-signed")
	}
	burned, err := f.s.GetNodeTLSAuthorityReservationLocal(requestID)
	if err != nil || burned.State != NodeTLSUncertain {
		t.Fatal("crash uncertainty did not burn reservation")
	}
	next := f.input
	next.RequestID = "synthetic_after_burn"
	next.ExpectedTLSEpochFloor = 1
	next.GrantNonce = r.Claims.Nonce
	if _, err := f.s.ReserveNodeTLSCandidate(next); !errors.Is(err, ErrNodeTLSAuthorityConflict) {
		t.Fatal("permanent nonce replay accepted")
	}
	next.GrantNonce = nodeTLSTestHash("after-burn-nonce")
	r2, err := f.s.ReserveNodeTLSCandidate(next)
	if err != nil {
		t.Fatal(err)
	}
	if r2.Claims.TLSEpoch != 2 || r2.Claims.Serial == r.Claims.Serial {
		t.Fatal("burned epoch or serial reused")
	}
	nodeTLSActivateFixture(t, f, r2)
}

func TestNodeTLSAuthorityNativeCurrentFences(t *testing.T) {
	if !nodeTLSNativeRequired(t) {
		return
	}
	for _, stage := range []string{"before_sign", "after_sign_before_commit", "before_ack", "before_activate", "current"} {
		t.Run(stage, func(t *testing.T) {
			f := newNodeTLSNativeFixture(t)
			r, err := f.s.ReserveNodeTLSCandidate(f.input)
			if err != nil {
				t.Fatal(err)
			}
			grant, err := e2ee.SignOwnerTLSLeafGrant(f.owner, r.Claims)
			if err != nil {
				t.Fatal(err)
			}
			action := NodeTLSAuthorityActionInput{RequestID: r.Claims.RequestID, NodeID: r.Claims.NodeID, CredentialDigest: f.digest, ExpectedVersion: r.RowVersion}
			if stage == "before_sign" {
				if _, err := f.s.db.Exec(`UPDATE client_devices_v2 SET state='REVOKED',version=version+1 WHERE device_id=?`, f.device.DeviceID); err != nil {
					t.Fatal(err)
				}
				if _, err := f.s.IssueNodeTLSLeaf(NodeTLSLeafIssueInput{NodeTLSAuthorityActionInput: action, Grant: grant}, f.issuer); !errors.Is(err, ErrNodeTLSAuthorityDenied) {
					t.Fatal("revoked approving device authorized signing")
				}
				return
			}
			if stage == "after_sign_before_commit" {
				issuing, err := f.s.BeginNodeTLSLeafIssue(NodeTLSLeafIssueInput{NodeTLSAuthorityActionInput: action, Grant: grant})
				if err != nil {
					t.Fatal(err)
				}
				p, _ := NodeTLSLeafParameters(r.Claims)
				leaf, err := f.issuer.IssueTLSLeaf(r.CSRPEM, p, nodeTLSNow())
				if err != nil {
					t.Fatal(err)
				}
				if _, err = f.s.db.Exec(`UPDATE fabric_node_credentials SET status='revoked' WHERE node_id=?`, r.Claims.NodeID); err != nil {
					t.Fatal(err)
				}
				action.ExpectedVersion = issuing.RowVersion
				if _, err = f.s.CommitNodeTLSLeaf(action, leaf.CertificatePEM); !errors.Is(err, ErrNodeTLSAuthorityDenied) {
					t.Fatal("changed credential accepted signed leaf")
				}
				return
			}
			if stage == "current" {
				active := nodeTLSActivateFixture(t, f, r)
				if _, err = f.s.db.Exec(`UPDATE node_control_key_bindings_v1 SET state='REVOKED',version=version+1 WHERE node_id=?`, r.Claims.NodeID); err != nil {
					t.Fatal(err)
				}
				current, err := f.s.CurrentNodeTransportBinding(r.Claims.NodeID)
				if err != nil || current.TLSAuthority != nil {
					t.Fatal("revoked NodeControl key left TLS active")
				}
				if _, err := f.s.IssueNodeTLSLeaf(NodeTLSLeafIssueInput{NodeTLSAuthorityActionInput: action, Grant: active.Grant}, f.issuer); !errors.Is(err, ErrNodeTLSAuthorityDenied) {
					t.Fatal("old grant replay bypassed current NodeControl")
				}
				return
			}
			signed, err := f.s.IssueNodeTLSLeaf(NodeTLSLeafIssueInput{NodeTLSAuthorityActionInput: action, Grant: grant}, f.issuer)
			if err != nil {
				t.Fatal(err)
			}
			ackClaims := e2ee.NodeTLSInstallAckClaims{Version: 1, GrantClaims: r.Claims, GrantDigest: e2ee.NodeTLSAuthorityDigest(grant), ReservationVersion: 1, LeafDERHash: signed.LeafDERHash, IssuedAt: nodeTLSStamp(nodeTLSNow()), ExpiresAt: r.Claims.ExpiresAt, Nonce: nodeTLSTestHash("fence-ack")}
			ack, err := e2ee.SignNodeTLSInstallAck(f.node, ackClaims)
			if err != nil {
				t.Fatal(err)
			}
			action.ExpectedVersion = signed.RowVersion
			if stage == "before_ack" {
				if _, err = f.s.db.Exec(`UPDATE client_devices_v2 SET version=version+1 WHERE device_id=?`, f.device.DeviceID); err != nil {
					t.Fatal(err)
				}
				if _, err = f.s.RecordNodeTLSInstallAck(NodeTLSInstallAckInput{NodeTLSAuthorityActionInput: action, InstallAck: ack}); !errors.Is(err, ErrNodeTLSAuthorityDenied) {
					t.Fatal("changed current device accepted install ACK")
				}
				return
			}
			installed, err := f.s.RecordNodeTLSInstallAck(NodeTLSInstallAckInput{NodeTLSAuthorityActionInput: action, InstallAck: ack})
			if err != nil {
				t.Fatal(err)
			}
			action.ExpectedVersion = installed.RowVersion
			activationClaims, err := f.s.PrepareNodeTLSActivation(action, nodeTLSTestHash("fence-active"))
			if err != nil {
				t.Fatal(err)
			}
			activation, err := e2ee.SignNodeTLSActivation(f.hub, activationClaims)
			if err != nil {
				t.Fatal(err)
			}
			if _, err = f.s.db.Exec(`UPDATE owner_approval_keys_v2 SET state='REVOKED',version=version+1 WHERE owner_id='owner_a'`); err != nil {
				t.Fatal(err)
			}
			if _, err = f.s.ActivateNodeTLSGrant(NodeTLSActivationInput{NodeTLSAuthorityActionInput: action, Activation: activation}); !errors.Is(err, ErrNodeTLSAuthorityDenied) {
				t.Fatal("revoked Owner approval activated a leaf")
			}
		})
	}
}
