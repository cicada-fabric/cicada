package pqtls

import (
	"context"
	"errors"
	"testing"
	"time"
)

func TestConfigurationDoesNotInventAuthorization(t *testing.T) {
	good := Config{CertificateFile: "synthetic.pem", PrivateKeyFile: "synthetic.key", TrustFile: "synthetic-ca.pem", LocalIdentity: Identity{Kind: "hub", HubID: "h", DNSName: "hub.synthetic.invalid"}, Peers: []Peer{{Identity: Identity{Kind: "node", HubID: "h", NodeID: "n", BindingEpoch: 1, DNSName: "node.synthetic.invalid"}, Pin: Pin{Kind: "certificate-sha256", SHA256: [32]byte{1}}}}}
	for _, name := range []string{"missing-pin", "unknown-pin-kind", "other-hub", "missing-node-epoch", "missing-node-id", "wildcard", "IP-not-DNS", "uppercase", "duplicate-pin", "unbounded-timeout", "wrong-direction", "unbounded-handshakes", "NUL-path"} {
		t.Run(name, func(t *testing.T) {
			cfg := good
			cfg.Peers = append([]Peer(nil), good.Peers...)
			switch name {
			case "missing-pin":
				cfg.Peers[0].Pin.SHA256 = [32]byte{}
			case "unknown-pin-kind":
				cfg.Peers[0].Pin.Kind = "TOFU"
			case "other-hub":
				cfg.Peers[0].Identity.HubID = "other"
			case "missing-node-epoch":
				cfg.Peers[0].Identity.BindingEpoch = 0
			case "missing-node-id":
				cfg.Peers[0].Identity.NodeID = ""
			case "wildcard":
				cfg.Peers[0].Identity.DNSName = "*.synthetic.invalid"
			case "IP-not-DNS":
				cfg.Peers[0].Identity.DNSName = "127.0.0.1"
			case "uppercase":
				cfg.Peers[0].Identity.DNSName = "NODE.synthetic.invalid"
			case "duplicate-pin":
				cfg.Peers = append(cfg.Peers, cfg.Peers[0])
			case "unbounded-timeout":
				cfg.HandshakeTimeout = 2 * time.Minute
			case "wrong-direction":
				cfg.LocalIdentity.Kind = "node"
			case "unbounded-handshakes":
				cfg.MaxPendingHandshakes = 65
			case "NUL-path":
				cfg.PrivateKeyFile = "synthetic.key\x00ignored"
			}
			if _, err := normalizeConfig(cfg, true); !errors.Is(err, ErrConfig) {
				t.Fatalf("invalid identity/policy accepted: %v", err)
			}
		})
	}
	copy, err := normalizeConfig(good, true)
	if err != nil {
		t.Fatal(err)
	}
	good.Peers[0].Pin.SHA256[0] = 2
	if copy.Peers[0].Pin.SHA256[0] != 1 {
		t.Fatal("caller mutated approved pin snapshot")
	}
}

func TestUninitializedClientCannotDial(t *testing.T) {
	var client Client
	if _, err := client.DialContext(context.Background(), "tcp", "127.0.0.1:9"); !errors.Is(err, ErrConfig) {
		t.Fatal("uninitialized client dial allowed")
	}
	if _, err := client.HTTPTransport("127.0.0.1:9"); !errors.Is(err, ErrConfig) {
		t.Fatal("uninitialized client transport allowed")
	}
}
