package main

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/cicada-ai/cicada/internal/e2ee"
)

func ownerTLSSignFixture(t *testing.T) (*e2ee.Identity, e2ee.OwnerTLSLeafGrantClaims, string, string) {
	t.Helper()
	owner, err := e2ee.NewIdentity()
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	if err := os.Chmod(dir, 0700); err != nil {
		t.Fatal(err)
	}
	secret, err := owner.MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}
	private := filepath.Join(dir, "owner-private")
	if err := os.WriteFile(private, secret, 0600); err != nil {
		t.Fatal(err)
	}
	clear(secret)
	at := time.Now().UTC().Truncate(time.Second).Add(-time.Second)
	hash := strings.Repeat("a", 64)
	c := e2ee.OwnerTLSLeafGrantClaims{Version: 2, RequestID: "SYNTHETIC-OPERATOR-TEST-ONLY", HubID: "synthetic-hub", NodeID: "synthetic-node", OwnerID: "synthetic-owner", OwnerKeyID: owner.Public().ID, OwnerKeyVersion: 1, ClientDeviceID: "synthetic-device", ClientDeviceVersion: 1, OwnerBindingID: "synthetic-binding", OwnerBindingVersion: 1, CredentialDigest: hash, CredentialVersion: 1, NodeControlKeyID: "synthetic-node-key", NodeControlKeyVersion: 1, NodeControlKeyEpoch: 1, NodeControlBindingVersion: 1, HubControlKeyID: "synthetic-hub-key", HubControlKeyVersion: 1, CSRDERHash: hash, SPKIDERHash: hash, IssuerSPKIHash: hash, IssuerDERHash: hash, RootDERHash: hash, IssuerGeneration: "synthetic-issuer", Role: "node", DNSName: "node.synthetic.invalid", Serial: strings.Repeat("0", 31) + "1", TLSEpoch: 1, NotBefore: at.Format(time.RFC3339), NotAfter: at.Add(time.Hour).Format(time.RFC3339), HubSPKIHash: hash, HubTrustAnchorDERHash: hash, HubPQOrigin: "https://hub.synthetic.invalid:7443", HubDialAddress: "192.0.2.1:7443", ApplicationOrigin: "http://127.0.0.1:8787", ApplicationProtocol: e2ee.NodeTLSApplicationProtocol, PQProfile: e2ee.NodeTLSPQProfile, IssuedAt: at.Format(time.RFC3339), ExpiresAt: at.Add(time.Hour).Format(time.RFC3339), Nonce: hash}
	path := filepath.Join(dir, "claims.json")
	data, _ := json.Marshal(c)
	if err := os.WriteFile(path, data, 0600); err != nil {
		t.Fatal(err)
	}
	return owner, c, private, path
}

func TestOwnerTLSLeafGrantSignExactIndependentReview(t *testing.T) {
	owner, c, private, path := ownerTLSSignFixture(t)
	data, _ := os.ReadFile(path)
	destination := filepath.Join(filepath.Dir(path), "grant")
	args := []string{"--private", private, "--claims", path, "--expect-claims-sha256", e2ee.NodeTLSAuthorityDigest(data), "--expect-owner-id", c.OwnerID, "--expect-owner-key-id", owner.Public().ID, "--expect-hub-id", c.HubID, "--expect-node-id", c.NodeID, "--output", destination}
	var output bytes.Buffer
	if err := ownerTLSLeafGrantSignCommand(args, &output); err != nil {
		t.Fatal(err)
	}
	proof, err := os.ReadFile(destination)
	if err != nil {
		t.Fatal(err)
	}
	got, err := e2ee.VerifyOwnerTLSLeafGrant(owner.Public(), time.Now().UTC(), proof)
	if err != nil || got != c {
		t.Fatal("exact Owner grant rejected", err)
	}
	if bytes.Contains(output.Bytes(), owner.Public().SigningPublic) || bytes.Contains(output.Bytes(), proof) {
		t.Fatal("CLI exposed full proof or key bytes")
	}
	if err := ownerTLSLeafGrantSignCommand(args, &output); err == nil {
		t.Fatal("existing grant overwritten")
	}
	for _, field := range []string{"--expect-claims-sha256", "--expect-owner-id", "--expect-owner-key-id", "--expect-hub-id", "--expect-node-id"} {
		t.Run(field, func(t *testing.T) {
			bad := append([]string(nil), args...)
			for i := range bad {
				if bad[i] == field {
					bad[i+1] = "wrong"
				}
				if bad[i] == "--output" {
					bad[i+1] = filepath.Join(filepath.Dir(path), "refused-"+field)
				}
			}
			if err := ownerTLSLeafGrantSignCommand(bad, &bytes.Buffer{}); err == nil {
				t.Fatal("unreviewed scope signed")
			}
		})
	}
}

func TestTLSProvisionNodeNeverAcceptsHubDatabase(t *testing.T) {
	dir := t.TempDir()
	os.Chmod(dir, 0700)
	for _, phase := range []string{"node-binding-request", "node-prepare", "node-stage", "node-apply"} {
		t.Run(phase, func(t *testing.T) {
			err := tlsProvisionLocalCommand([]string{phase, "--db", filepath.Join(dir, "must-not-create.db"), "--state-dir", dir, "--node-id", "synthetic-node", "--hub-id", "synthetic-hub", "--origin", "http://127.0.0.1:8787", "--output", filepath.Join(dir, "must-not-create-output")}, &bytes.Buffer{})
			if err == nil {
				t.Fatal("Node phase accepted Hub database")
			}
			if _, err := os.Lstat(filepath.Join(dir, "must-not-create.db")); !os.IsNotExist(err) {
				t.Fatal("Node phase touched Hub database")
			}
		})
	}
}
