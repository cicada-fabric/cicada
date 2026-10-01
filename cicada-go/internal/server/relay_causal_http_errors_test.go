package server

import (
	"net/http"
	"net/http/httptest"
	"testing"

	fabricpkg "github.com/cicada-ai/cicada/internal/fabric"
	"github.com/cicada-ai/cicada/internal/store"
)

func TestCausalBudgetIsPermanentHTTPConflictAcrossSealedRoutes(t *testing.T) {
	for name, write := range map[string]func(http.ResponseWriter, error){
		"Network Fabric":     networkV2Error,
		"same-Group":         relayNodeSameGroupSealedWriteError,
		"Communication Link": relayNodeSealedWriteError,
	} {
		t.Run(name, func(t *testing.T) {
			response := httptest.NewRecorder()
			write(response, store.ErrRelayCausalBudget)
			if response.Code != http.StatusConflict {
				t.Fatalf("permanent ancestry budget status=%d, want 409", response.Code)
			}
			if response.Header().Get("Retry-After") != "" {
				t.Fatalf("permanent ancestry budget carried Retry-After: %q", response.Header().Get("Retry-After"))
			}
		})
	}
	response := httptest.NewRecorder()
	networkV2Error(response, fabricpkg.ErrConflict)
	if response.Code != http.StatusConflict {
		t.Fatalf("Fabric-mapped permanent conflict status=%d, want 409", response.Code)
	}
}

func TestCausalTemporaryAdmissionRemainsRetryable429(t *testing.T) {
	response := httptest.NewRecorder()
	networkV2Error(response, &store.RelayAdmissionError{Scope: "synthetic", Limit: 4,
		Pending: 4, RetryAfterSeconds: 9})
	if response.Code != http.StatusTooManyRequests || response.Header().Get("Retry-After") != "9" {
		t.Fatalf("temporary Relay capacity status=%d Retry-After=%q, want 429/9",
			response.Code, response.Header().Get("Retry-After"))
	}
	response = httptest.NewRecorder()
	networkV2Error(response, store.ErrNetworkBroadcastPending)
	if response.Code != http.StatusTooEarly || response.Header().Get("Retry-After") != "" {
		t.Fatalf("uncommitted metadata status=%d Retry-After=%q, want 425 without Retry-After",
			response.Code, response.Header().Get("Retry-After"))
	}
}
