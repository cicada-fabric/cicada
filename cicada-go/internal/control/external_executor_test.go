package control

import (
	"context"
	"net"
	"net/http"
	"net/url"
	"testing"
)

func TestReadOnlyExternalActionBoundary(t *testing.T) {
	for _, test := range []struct {
		kind, method string
		allowed      bool
	}{
		{kind: "fetch", method: "GET", allowed: true},
		{kind: "search", method: "HEAD", allowed: true},
		{kind: "download", method: "GET", allowed: true},
		{kind: "form_fill", method: "GET"},
		{kind: "fetch", method: "POST"},
	} {
		if readOnlyExternalAction(test.kind, test.method) != test.allowed {
			t.Errorf("read-only action %s/%s allowed=%v", test.kind, test.method, test.allowed)
		}
	}
}

func TestExternalNetworkRejectsPrivateDestinations(t *testing.T) {
	for _, address := range []string{"127.0.0.1", "10.0.0.1", "::1", "fc00::1"} {
		if !privateAddress(net.ParseIP(address)) {
			t.Errorf("private address was accepted: %s", address)
		}
	}
	target, err := url.Parse("http://localhost:8080")
	if err != nil {
		t.Fatal(err)
	}
	if err := validateResolvedHost(context.Background(), target); err == nil {
		t.Fatal("localhost resolved as an external destination")
	}
}

func TestExternalRedirectPolicyRejectsCredentialAndDowngrade(t *testing.T) {
	client := safeExternalHTTPClient()
	for _, raw := range []string{"https://example.com/?token=secret", "https://example.com/#fragment"} {
		target, err := url.Parse(raw)
		if err != nil {
			t.Fatal(err)
		}
		request := httptestRequest(target)
		if err := client.CheckRedirect(request, nil); err == nil {
			t.Errorf("unsafe redirect was accepted: %s", raw)
		}
	}
}

func httptestRequest(target *url.URL) *http.Request {
	request, _ := http.NewRequest("GET", target.String(), nil)
	return request
}
