package pqtls

import (
	"context"
	"errors"
	"strings"
	"testing"
)

func TestIPDialAddressCanonical(t *testing.T) {
	for _, s := range []string{"192.0.2.1:1", "192.0.2.1:65535", "[2001:db8::1]:7443", "[::1]:443"} {
		if err := ValidateIPDialAddress(s); err != nil {
			t.Fatalf("canonical socket rejected: %s", s)
		}
	}
	for _, s := range []string{"", "hub.synthetic.invalid:443", "127.1:443", "0127.0.0.1:443", "127.0.0.1", "127.0.0.1:0", "127.0.0.1:65536", "127.0.0.1:0443", "127.0.0.1:+443", "127.0.0.1: 443", "[127.0.0.1]:443", "::1:443", "[0:0:0:0:0:0:0:1]:443", "[2001:DB8::1]:443", "[fe80::1%eth0]:443", "[::ffff:192.0.2.1]:443", "https://192.0.2.1:443", "0.0.0.0:443", "[::]:443", "224.0.0.1:443", "[ff02::1]:443", "192.0.2.1:443/", "192.0.2.1:443\x00"} {
		if err := ValidateIPDialAddress(s); !errors.Is(err, ErrConfig) {
			t.Fatalf("ambiguous socket accepted: %q", s)
		}
	}
}
func TestIPDialTransportRestrictsLogicalTarget(t *testing.T) {
	c := &Client{cfg: Config{Peers: []Peer{{}}}}
	transport, err := c.HTTPTransportWithDialAddress("hub.synthetic.invalid:443", "192.0.2.1:7443")
	if err != nil {
		t.Fatal(err)
	}
	if transport.Proxy != nil {
		t.Fatal("physical dial can enter proxy")
	}
	for _, target := range []string{"other.synthetic.invalid:443", "192.0.2.1:7443", "hub.synthetic.invalid:7443"} {
		if _, err := transport.DialTLSContext(context.Background(), "tcp", target); !errors.Is(err, ErrIdentity) {
			t.Fatal("unapproved logical target reached socket")
		}
	}
	if _, err := transport.DialContext(context.Background(), "tcp", "hub.synthetic.invalid:443"); !errors.Is(err, ErrProfile) {
		t.Fatal("plaintext dial accepted")
	}
	for _, address := range []string{"hub.synthetic.invalid:443", "192.0.2.1:0", "[::1%zone]:443", strings.Repeat("0", 300)} {
		if _, err := c.HTTPTransportWithDialAddress("hub.synthetic.invalid:443", address); !errors.Is(err, ErrConfig) {
			t.Fatal("non-IP transport accepted")
		}
	}
}
