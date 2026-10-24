package n3_test

import (
	"net/http"
	"sync/atomic"
	"testing"
	"time"

	"github.com/cicada-ai/cicada/internal/hubtransport"
)

// Qualification only: the synthetic endpoint receives no actual account or
// pairing request. The actual case observes App persistence and Hub commit
// independently before selecting the corresponding opaque TCP cut.
func TestN3NodePairTrustOpaqueFaultBoundary(t *testing.T) {
	for _, clientSide := range []bool{true, false} {
		name := "after-response"
		if clientSide {
			name = "before-forward-original-retries"
		}
		t.Run(name, func(t *testing.T) {
			a := newDirectIPTLSAdversary(t)
			now := time.Now().UTC()
			leaf := a.leaf(t, a.descriptor.Claims.ServerName, now.Add(-time.Hour), now.Add(time.Hour), a.serviceKey)
			target := newDirectIPTLSTrap(t, http.StatusNoContent, "", leaf)
			var pending atomic.Bool
			fault := newDirectIPCipherFaultDirection(t, target.server.Listener.Addr().String(), pending.Load, clientSide, clientSide)
			client := must(hubtransport.NewHTTPClient(a.descriptor, fault.listener.Addr().String(), 3*time.Second))
			t.Cleanup(client.CloseIdleConnections)
			for _, armed := range []bool{false, true} {
				fault.armed.Store(armed)
				response, err := directIPTLSRequest(t, client, a.descriptor.Claims.Origin+"/synthetic-pairing-fault-control", nil)
				if err != nil || response.StatusCode != http.StatusNoContent || fault.cuts.Load() != 0 {
					t.Fatal("opaque pairing cut fired before the independent pending signal")
				}
			}
			baseline := target.posts.Load()
			pending.Store(true)
			cuts := int64(1)
			if clientSide {
				cuts = 2 // Keep the original retry cut until reconcile is durable.
			}
			for attempt := int64(0); attempt < cuts; attempt++ {
				response, err := directIPTLSRequest(t, client, a.descriptor.Claims.Origin+"/synthetic-pairing-original", nil)
				if response != nil {
					response.Body.Close()
				}
				if err == nil || fault.cuts.Load() != attempt+1 || !fault.dropped.Load() || fault.bytes.Load() == 0 {
					t.Fatal("opaque pairing cut did not produce its bounded transport uncertainty")
				}
			}
			want := baseline + 1
			if clientSide {
				want = baseline
			}
			if target.posts.Load() != want {
				t.Fatal("pairing cut reached the wrong side of the independently observed request")
			}
			pending.Store(false)
			fault.armed.Store(false)
			client.CloseIdleConnections()
			response, err := directIPTLSRequest(t, client, a.descriptor.Claims.Origin+"/synthetic-pairing-reconcile-control", nil)
			if err != nil || response.StatusCode != http.StatusNoContent || target.posts.Load() != want+1 || fault.cuts.Load() != cuts {
				t.Fatal("original end-to-end TLS could not resume after the pairing cut")
			}
		})
	}
}
