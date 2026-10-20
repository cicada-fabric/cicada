// Package installationclient consumes the installation-registration contract.
// It owns no server policy, role assignment, background worker or public DTO.
package installationclient

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net/http"

	wire "github.com/cicada-ai/cicada/internal/hubaccountwire"
)

type HTTPDoer interface {
	Do(*http.Request) (*http.Response, error)
}

var (
	ErrUnavailable = errors.New("installation registration is unavailable")
	ErrUnknown     = errors.New("installation response is unknown; retain the original request")
	ErrState       = errors.New("protected installation recovery state is invalid")
	ErrStorage     = errors.New("installation storage requires close and reopen")
	ErrPending     = errors.New("recover the original installation request first")
	ErrClosed      = errors.New("installation client is closed")
)

// The caller supplies an independently verified canonical origin and Hub pin.
// No body, status text, remote error or redirect destination enters diagnostics.
func readCapabilities(ctx context.Context, httpClient HTTPDoer, origin string) (wire.InstallationCapabilities, error) {
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, origin+wire.InstallationCapabilitiesPath, nil)
	if err != nil || httpClient == nil {
		return wire.InstallationCapabilities{}, ErrUnavailable
	}
	request.Header.Set("Accept", "application/json")
	response, err := httpClient.Do(request)
	if err != nil || response == nil || response.Body == nil {
		if response != nil && response.Body != nil {
			_ = response.Body.Close()
		}
		return wire.InstallationCapabilities{}, ErrUnavailable
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK || response.Request != nil && response.Request.URL.String() != request.URL.String() {
		return wire.InstallationCapabilities{}, ErrUnavailable
	}
	raw, err := io.ReadAll(io.LimitReader(response.Body, (8<<10)+1))
	if err != nil || len(raw) > 8<<10 {
		clear(raw)
		return wire.InstallationCapabilities{}, ErrUnavailable
	}
	defer clear(raw)
	capabilities, err := wire.DecodeInstallationCapabilities(raw)
	if err != nil {
		return wire.InstallationCapabilities{}, ErrUnavailable
	}
	return capabilities, nil
}

func postOriginal(ctx context.Context, httpClient HTTPDoer, origin, operation string, original []byte) ([]byte, error) {
	path := wire.InstallationHTTPPath(operation)
	maximum := wire.MaxInstallationPacketBytes
	if operation == wire.OperationInstallationReconcile {
		maximum = wire.MaxInstallationReconcilePacketBytes
	}
	if path == "" || len(original) == 0 || len(original) > maximum {
		return nil, ErrState
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, origin+path, bytes.NewReader(original))
	if err != nil || httpClient == nil {
		return nil, ErrUnknown
	}
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("Accept", "application/json")
	request.Header.Set("Origin", origin)
	response, err := httpClient.Do(request)
	if err != nil || response == nil || response.Body == nil {
		if response != nil && response.Body != nil {
			_ = response.Body.Close()
		}
		return nil, ErrUnknown
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK || response.Request != nil && response.Request.URL.String() != request.URL.String() {
		return nil, ErrUnknown // Unauthenticated HTTP cannot settle the original.
	}
	maximum = wire.MaxInstallationReceiptBytes
	if operation == wire.OperationInstallationReconcile {
		maximum = wire.MaxInstallationReconcilePacketBytes
	}
	raw, err := io.ReadAll(io.LimitReader(response.Body, int64(maximum)+1))
	if err != nil || len(raw) > maximum {
		clear(raw)
		return nil, ErrUnknown
	}
	return raw, nil
}
