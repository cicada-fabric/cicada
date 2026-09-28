package workspace

import (
	"context"
	"net"
	"testing"
)

func TestPublicGitHostRejectsSharedAddressResolution(t *testing.T) {
	for _, raw := range []string{"100.64.0.1", "100.100.100.200", "100.127.255.254", "127.0.0.1", "::1"} {
		if publicIP(net.ParseIP(raw)) {
			t.Errorf("non-public Git address accepted: %s", raw)
		}
	}
	for _, raw := range []string{"100.63.255.255", "100.128.0.0", "8.8.8.8"} {
		if !publicIP(net.ParseIP(raw)) {
			t.Errorf("public Git address rejected: %s", raw)
		}
	}
	previous := lookupIP
	lookupIP = func(_ context.Context, host string) ([]net.IPAddr, error) {
		if host != "synthetic.example" {
			t.Fatalf("unexpected host %q", host)
		}
		return []net.IPAddr{{IP: net.ParseIP("8.8.8.8")}, {IP: net.ParseIP("100.100.100.200")}}, nil
	}
	t.Cleanup(func() { lookupIP = previous })
	if err := validatePublicGitHost(context.Background(), "https://synthetic.example/repo.git"); err == nil {
		t.Fatal("Git host resolving to shared-address destination was accepted")
	}
}
