package main

import "testing"

func TestServeRequiresTokenOutsideLoopback(t *testing.T) {
	for _, host := range []string{"127.0.0.1", "::1", "localhost"} {
		if err := validateServeExposure(host, ""); err != nil {
			t.Fatalf("loopback host %q required a token: %v", host, err)
		}
	}
	for _, host := range []string{"0.0.0.0", "::", "192.0.2.10", "control.example"} {
		if err := validateServeExposure(host, ""); err == nil {
			t.Fatalf("non-loopback host %q accepted an empty API token", host)
		}
		if err := validateServeExposure(host, "configured-token"); err != nil {
			t.Fatalf("non-loopback host %q rejected configured auth: %v", host, err)
		}
	}
}
