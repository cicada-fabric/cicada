package nodewire

import (
	"testing"
)

func TestNodeTLSIPLocatorCurrentSealedResponse(t *testing.T) {
	node, hub, b, q, s, at := tlsCurrentFixture(t)
	s.CurrentAuthority.Claims.Version = 2
	s.CurrentAuthority.Claims.HubDialAddress = "[2001:db8::1]:7443"
	packet, err := SealTLSCurrentRequest(node, b, q, at)
	if err != nil {
		t.Fatal(err)
	}
	reply, err := SealTLSCurrentResponse(hub, b, q, packet, s, at)
	if err != nil {
		t.Fatal("v2 current shape rejected", err)
	}
	got, err := OpenTLSCurrentResponse(node, b, q, packet, reply, at)
	if err != nil || got.CurrentAuthority.Claims != s.CurrentAuthority.Claims {
		t.Fatal("fresh sealed response lost exact locator", err)
	}
	for _, address := range []string{"hub.synthetic.invalid:7443", "[::]:7443", "[fe80::1%zone]:7443", "192.0.2.1:00080", ""} {
		bad := s
		bad.CurrentAuthority.Claims.HubDialAddress = address
		if _, err := SealTLSCurrentResponse(hub, b, q, packet, bad, at); err == nil {
			t.Fatal("invalid current locator sealed")
		}
	}
	bad := s
	bad.CurrentAuthority.Claims.Version = 1
	if _, err := SealTLSCurrentResponse(hub, b, q, packet, bad, at); err == nil {
		t.Fatal("v1 current authority reinterpreted IP override")
	}
}
