package n3_test

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
)

// This tests opaque TCP fault placement only. Its upstream is deliberately
// synthetic, not a Hub response or an authorization/registration oracle.
func TestN3HarnessMethodSpecificFaultBarrier(t *testing.T) {
	var gets, posts atomic.Int64
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case http.MethodGet:
			gets.Add(1)
		case http.MethodPost:
			posts.Add(1)
		}
		_, _ = io.WriteString(w, "SYNTHETIC OPAQUE TRANSPORT ONLY")
	}))
	defer upstream.Close()
	proxy := newFaultProxy(t, upstream.URL)
	const path = "/synthetic-same-path"
	_, release := proxy.armMethod(path, http.MethodPost, "before-forward", 1)
	defer release()
	for range 2 {
		response, err := proxy.client.Get(proxy.server.URL + path)
		if err != nil || response.StatusCode != http.StatusOK {
			t.Fatal("POST fault blocked the preceding discovery GET")
		}
		response.Body.Close()
	}
	response, err := proxy.client.Post(proxy.server.URL+path, "application/octet-stream", strings.NewReader("SYNTHETIC ORIGINAL PACKET"))
	if response != nil {
		response.Body.Close()
	}
	if err == nil || gets.Load() != 2 || posts.Load() != 0 {
		t.Fatal("method-specific pre-forward loss did not preserve exact request ordering")
	}
	trace := proxy.snapshot()
	if len(trace) != 3 || trace[0].Method != http.MethodGet || trace[1].Method != http.MethodGet || trace[2].Method != http.MethodPost ||
		!trace[0].Forwarded || !trace[1].Forwarded || trace[2].Forwarded {
		t.Fatal("fault evidence omitted the actual method or changed forwarding history")
	}
}
