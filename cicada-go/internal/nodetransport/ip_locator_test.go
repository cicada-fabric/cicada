package nodetransport

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	"github.com/cicada-ai/cicada/internal/e2ee"
	"github.com/cicada-ai/cicada/internal/store"
)

func ipLocatorConfig() Config {
	return Config{Version: 2, Role: "node", Origin: "https://hub.synthetic.invalid:7443", ApplicationOrigin: "https://192.0.2.1:8443", DialAddress: "192.0.2.1:7443", Identity: Identity{Kind: "node", HubID: "synthetic-hub", NodeID: "synthetic-node", TLSEpoch: 1, DNSName: "node.synthetic.invalid"}, Peers: []Approval{{Identity: Identity{Kind: "hub", HubID: "synthetic-hub", DNSName: "hub.synthetic.invalid"}, PinKind: "spki-sha256", PinSHA256: strings.Repeat("ab", 32)}}}
}
func TestIPLocatorConfigurationVersionAndAuthority(t *testing.T) {
	c := ipLocatorConfig()
	if err := c.Validate("node"); err != nil {
		t.Fatal(err)
	}
	for name, mutate := range map[string]func(*Config){
		"v1-with-ip-override":   func(v *Config) { v.Version = 1 },
		"missing-locator":       func(v *Config) { v.DialAddress = "" },
		"dns-locator":           func(v *Config) { v.DialAddress = "hub.synthetic.invalid:7443" },
		"foreign-hub":           func(v *Config) { v.Peers[0].Identity.HubID = "foreign-hub" },
		"service-san":           func(v *Config) { v.Peers[0].Identity.DNSName = "foreign.synthetic.invalid" },
		"origin-is-ip-identity": func(v *Config) { v.Origin = "https://192.0.2.1:7443" },
		"missing-pin":           func(v *Config) { v.Peers[0].PinSHA256 = strings.Repeat("0", 64) },
		"missing-epoch":         func(v *Config) { v.Identity.TLSEpoch = 0 },
	} {
		t.Run(name, func(t *testing.T) {
			v := ipLocatorConfig()
			mutate(&v)
			if v.Validate("node") == nil {
				t.Fatal("ambiguous authority accepted")
			}
		})
	}
	c.Version = 1
	c.DialAddress = ""
	if err := c.Validate("node"); err != nil {
		t.Fatal("legacy DNS config changed", err)
	}
	wire, _ := json.Marshal(c)
	if strings.Contains(string(wire), "dial_address") {
		t.Fatal("legacy wire changed")
	}
}
func TestIPLocatorPreparationExactBinding(t *testing.T) {
	r := installDummyRequest()
	r.HubDialAddress = "[2001:db8::1]:7443"
	if !validPreparation(r) {
		t.Fatal("canonical IP preparation rejected")
	}
	p := tlsPreparation{Version: 2, Request: r, Binding: TLSLocalBinding{}, Floor: 0}
	c := e2ee.OwnerTLSLeafGrantClaims{Version: 2, RequestID: r.RequestID, DNSName: r.DNSName, HubPQOrigin: r.HubPQOrigin, HubDialAddress: r.HubDialAddress, ApplicationOrigin: r.ApplicationOrigin, HubSPKIHash: r.HubSPKIHash, HubTrustAnchorDERHash: r.HubTrustAnchorDERHash, IssuerGeneration: r.IssuerGeneration, IssuerSPKIHash: r.IssuerSPKIHash, IssuerDERHash: r.IssuerDERHash, RootDERHash: r.RootDERHash, TLSEpoch: 1}
	if !preparationMatches(p, c) {
		t.Fatal("exact independent preparation did not match")
	}
	for name, mutate := range map[string]func(*e2ee.OwnerTLSLeafGrantClaims){
		"locator":    func(v *e2ee.OwnerTLSLeafGrantClaims) { v.HubDialAddress = "[2001:db8::2]:7443" },
		"version":    func(v *e2ee.OwnerTLSLeafGrantClaims) { v.Version = 1 },
		"hub":        func(v *e2ee.OwnerTLSLeafGrantClaims) { v.HubID = "foreign" },
		"pin":        func(v *e2ee.OwnerTLSLeafGrantClaims) { v.HubSPKIHash = strings.Repeat("c", 64) },
		"san-origin": func(v *e2ee.OwnerTLSLeafGrantClaims) { v.HubPQOrigin = "https://foreign.synthetic.invalid" },
		"epoch":      func(v *e2ee.OwnerTLSLeafGrantClaims) { v.TLSEpoch = 0 },
	} {
		t.Run(name, func(t *testing.T) {
			v := c
			mutate(&v)
			if preparationMatches(p, v) {
				t.Fatal("unapproved preparation substitution accepted")
			}
		})
	}
	for _, address := range []string{"hub.synthetic.invalid:7443", "[fe80::1%eth0]:7443", "192.0.2.1:00080", "192.0.2.1:0"} {
		r.HubDialAddress = address
		if validPreparation(r) {
			t.Fatal("noncanonical preparation accepted")
		}
	}
	r = installDummyRequest()
	p.Request = r
	p.Version = 1
	c.Version = 1
	c.HubDialAddress = ""
	if !preparationMatches(p, c) {
		t.Fatal("legacy preparation no longer matches")
	}
	wire, _ := json.Marshal(p)
	if strings.Contains(string(wire), "HubDialAddress") {
		t.Fatal("v1 preparation bytes extended")
	}
}

func TestIPLocatorNativeInstallCheckedLoadAndCurrentAuthority(t *testing.T) {
	if !installNativeEnabled(t) {
		return
	}
	i, s, ca, owner, hub := installSignedIPFixture(t, "192.0.2.1:7443")
	// Even a newly signed alternative locator cannot replace independently
	// retained preparation. It must have its own maintenance cycle.
	bad := s
	bad.Claims.HubDialAddress = "192.0.2.2:7443"
	var err error
	bad.Grant, err = e2ee.SignOwnerTLSLeafGrant(owner, bad.Claims)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := i.Stage(bad, ca.chain, ca.root, ca.root, ca.at); err == nil {
		t.Fatal("Owner proof bypassed independent preparation")
	}
	s = installActivate(t, i, s, ca, hub)
	cfg, err := i.Apply(s, ca.at)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Version != 2 || cfg.DialAddress != s.Claims.HubDialAddress || cfg.Peers[0].Identity.DNSName != "hub.synthetic.invalid" {
		t.Fatal("IP locator became service identity")
	}
	loaded, err := i.LoadActive(ca.at)
	if err != nil || loaded.DialAddress != cfg.DialAddress {
		t.Fatal("checked IP load failed", err)
	}
	b, err := ReadAcceptedTLSRuntimeBinding(i.StateRoot, i.WriterRoot, i.HubID, i.NodeID)
	if err != nil || b.Control.HubID != i.HubID {
		t.Fatal("runtime preparation adapter rejected v2", err)
	}
	o := runtimeTestOptions(i)
	o.QueryCurrent = func(_ context.Context, c *Config) (*store.NodeTLSAuthoritySnapshot, error) {
		if c.DialAddress != s.Claims.HubDialAddress {
			t.Fatal("runtime query lost exact socket locator")
		}
		copy := s
		return &copy, nil
	}
	runtime, err := OpenRuntime(context.Background(), o)
	if err != nil {
		t.Fatal("v2 runtime checked restart rejected", err)
	}
	if err := runtime.Close(); err != nil {
		t.Fatal(err)
	}
	for _, read := range []int{1, 2} {
		calls := 0
		o.QueryCurrent = func(context.Context, *Config) (*store.NodeTLSAuthoritySnapshot, error) {
			calls++
			copy := s
			if calls == read {
				copy.Claims.HubDialAddress = "192.0.2.2:7443"
			}
			return &copy, nil
		}
		published, err := OpenRuntime(context.Background(), o)
		if published != nil {
			published.Close()
			t.Fatal("changed fresh authority locator published runtime")
		}
		if err == nil {
			t.Fatal("fresh authority mismatch ignored")
		}
	}

	current := s
	current.Claims.HubDialAddress = "192.0.2.2:7443"
	i.CurrentActiveAuthority = func() (*store.NodeTLSAuthoritySnapshot, error) { return &current, nil }
	if _, err := i.LoadActive(ca.at); err == nil {
		t.Fatal("current authority locator mismatch ignored")
	}
}
