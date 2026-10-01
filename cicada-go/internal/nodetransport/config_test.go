package nodetransport

import (
	"encoding/json"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func testConfig() Config {
	return Config{Version: 1, Role: "hub", Listen: "127.0.0.1:0", Identity: Identity{Kind: "hub", HubID: "synthetic-hub", DNSName: "hub.synthetic.invalid"}, Peers: []Approval{{Identity: Identity{Kind: "node", HubID: "synthetic-hub", NodeID: "synthetic-node", DNSName: "node.synthetic.invalid", TLSEpoch: 17}, PinKind: "certificate-sha256", PinSHA256: strings.Repeat("ab", 32), OwnerID: "synthetic-owner", OwnerKeyID: "synthetic-key", BindingID: "synthetic-binding", BindingVersion: 3, CredentialVersion: 5}}}
}

func TestApplicationOriginSelectionDoesNotChangePeerAuthority(t *testing.T) {
	for _, origin := range []string{"https://original.synthetic.invalid", "http://127.0.0.1:8787", "http://[::1]:8787"} {
		if err := validateApplicationOrigin(origin); err != nil {
			t.Fatalf("explicit logical origin rejected: %v", err)
		}
	}
	for _, origin := range []string{"http://public.synthetic.invalid", "https://user@original.synthetic.invalid", "https://original.synthetic.invalid/path", "https://original.synthetic.invalid?query", "https://original.synthetic.invalid#fragment"} {
		if validateApplicationOrigin(origin) == nil {
			t.Fatal("ambiguous logical origin accepted")
		}
	}
	transport := &originTransport{origin: "https://node.synthetic.invalid", logicalOrigin: "https://original.synthetic.invalid"}
	for _, origin := range []string{"https://node.synthetic.invalid", "https://other.synthetic.invalid", "http://original.synthetic.invalid"} {
		r, _ := http.NewRequest(http.MethodPost, origin+"/v2/node/control/rpc", nil)
		if _, err := transport.RoundTrip(r); err == nil {
			t.Fatal("unapproved logical origin reached dial")
		}
	}
	r, _ := http.NewRequest(http.MethodPost, "https://original.synthetic.invalid/v2/node/control/rpc", nil)
	r.Host = "other.synthetic.invalid"
	if _, err := transport.RoundTrip(r); err == nil {
		t.Fatal("unapproved Host reached dial")
	}
	for _, path := range []string{"/v2/relay/nodes/a/events", "/v2/fabric/node/join", "/v2/fabric/networks/n/whoami", "/v2/node/control/rpc", "/v2/artifacts/a"} {
		if !IsEnrolledNodePath(path) {
			t.Fatal("peer path not protected")
		}
	}
	for _, path := range []string{"/v2/client/rpc", "/v2/client/identity", "/v2/nodes/device-code", "/v2/node/device-code/pending/status", "/v2/node/identity", "/v1/machines", "/v2/artifacts-unrelated"} {
		if IsEnrolledNodePath(path) {
			t.Fatal("bootstrap/Client/Manager path remapped")
		}
	}
}

func TestPrivateNodeTransportConfigRejectsAmbiguousAuthority(t *testing.T) {
	for _, tc := range []struct {
		name   string
		mutate func(*Config)
	}{
		{"missing-owner", func(c *Config) { c.Peers[0].OwnerID = "" }},
		{"missing-key", func(c *Config) { c.Peers[0].OwnerKeyID = "" }},
		{"missing-binding", func(c *Config) { c.Peers[0].BindingID = "" }},
		{"binding-zero", func(c *Config) { c.Peers[0].BindingVersion = 0 }},
		{"credential-zero", func(c *Config) { c.Peers[0].CredentialVersion = 0 }},
		{"tls-epoch-zero", func(c *Config) { c.Peers[0].Identity.TLSEpoch = 0 }},
		{"foreign-hub", func(c *Config) { c.Peers[0].Identity.HubID = "other" }},
		{"duplicate-node", func(c *Config) { p := c.Peers[0]; p.PinSHA256 = strings.Repeat("cd", 32); c.Peers = append(c.Peers, p) }},
		{"zero-pin", func(c *Config) { c.Peers[0].PinSHA256 = strings.Repeat("0", 64) }},
		{"invalid-pin", func(c *Config) { c.Peers[0].PinKind = "tofu" }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c := testConfig()
			tc.mutate(&c)
			if c.Validate("hub") == nil {
				t.Fatal("accepted ambiguous transport authority")
			}
		})
	}
	c := testConfig()
	if err := c.Validate("hub"); err != nil {
		t.Fatal(err)
	}
	if c.TLSConfig().Peers[0].Identity.BindingEpoch != 17 || c.Peers[0].BindingVersion != 3 || c.Peers[0].CredentialVersion != 5 {
		t.Fatal("TLS and business epochs conflated")
	}
}

func TestPrivateNodeTransportFileBoundary(t *testing.T) {
	root := t.TempDir()
	c := testConfig()
	for _, p := range []string{"cert.pem", "key.pem", "ca.pem"} {
		if err := os.WriteFile(filepath.Join(root, p), []byte("SYNTHETIC CONFIG TEST ONLY"), 0600); err != nil {
			t.Fatal(err)
		}
	}
	c.CertificateFile = "cert.pem"
	c.PrivateKeyFile = "key.pem"
	c.TrustFile = "ca.pem"
	path := filepath.Join(root, "transport.json")
	data, _ := json.Marshal(c)
	write := func(data []byte, mode os.FileMode) {
		t.Helper()
		if err := os.WriteFile(path, data, 0600); err != nil {
			t.Fatal(err)
		}
		if err := os.Chmod(path, mode); err != nil {
			t.Fatal(err)
		}
	}
	write(data, 0600)
	loaded, err := Load(path, "hub")
	if err != nil || loaded.PrivateKeyFile != filepath.Join(root, "key.pem") {
		t.Fatal("private relative config not loaded")
	}
	t.Run("public-config", func(t *testing.T) {
		write(data, 0644)
		if _, err := Load(path, "hub"); err == nil {
			t.Fatal("public config accepted")
		}
	})
	t.Run("trailing-json", func(t *testing.T) {
		write(append(data, []byte("{}")...), 0600)
		if _, err := Load(path, "hub"); err == nil {
			t.Fatal("trailing config accepted")
		}
	})
	t.Run("unknown-field", func(t *testing.T) {
		write(append([]byte(`{"unknown":1,`), data[1:]...), 0600)
		if _, err := Load(path, "hub"); err == nil {
			t.Fatal("unknown config accepted")
		}
	})
	t.Run("public-key", func(t *testing.T) {
		write(data, 0600)
		if err := os.Chmod(filepath.Join(root, "key.pem"), 0644); err != nil {
			t.Fatal(err)
		}
		if _, err := Load(path, "hub"); err == nil {
			t.Fatal("public key accepted")
		}
		os.Chmod(filepath.Join(root, "key.pem"), 0600)
	})
	t.Run("symlink-config", func(t *testing.T) {
		write(data, 0600)
		link := filepath.Join(root, "linked.json")
		if err := os.Symlink(path, link); err != nil {
			t.Fatal(err)
		}
		if _, err := Load(link, "hub"); err == nil {
			t.Fatal("linked config accepted")
		}
	})
}

func TestNodeTransportOriginRejectsDowngradeAndCredentials(t *testing.T) {
	for _, origin := range []string{"http://hub.synthetic.invalid", "https://user:password@hub.synthetic.invalid", "https://hub.synthetic.invalid/path", "https://hub.synthetic.invalid?query", "https://hub.synthetic.invalid#fragment", "https://"} {
		t.Run(origin, func(t *testing.T) {
			if _, err := ParseOrigin(origin); err == nil {
				t.Fatal("unsafe origin accepted")
			}
		})
	}
}
