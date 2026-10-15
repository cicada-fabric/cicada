package appcore

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	wire "github.com/cicada-ai/cicada/internal/hubaccountwire"
)

const maxMetadataBytes = 64 * 1024

type HTTPDoer interface {
	Do(*http.Request) (*http.Response, error)
}

var accountRoutes = map[string]string{
	wire.OperationClaimPrepare:   "/v2/owner/account/claim/prepare",
	wire.OperationClaimComplete:  "/v2/owner/account/claim/complete",
	wire.OperationLoginPrepare:   "/v2/owner/account/login/prepare",
	wire.OperationLoginComplete:  "/v2/owner/account/login/complete",
	wire.OperationSessionInspect: "/v2/owner/account/session/inspect",
	wire.OperationSessionLogout:  "/v2/owner/account/session/logout",
}

func NewHTTPClient() *http.Client {
	transport := &http.Transport{
		Proxy:                 nil,
		TLSClientConfig:       &tls.Config{MinVersion: tls.VersionTLS13},
		ForceAttemptHTTP2:     true,
		DisableKeepAlives:     false,
		MaxIdleConns:          8,
		MaxIdleConnsPerHost:   2,
		IdleConnTimeout:       30 * time.Second,
		TLSHandshakeTimeout:   10 * time.Second,
		ResponseHeaderTimeout: 10 * time.Second,
	}
	return &http.Client{Transport: transport, Timeout: 20 * time.Second,
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
}

func getHubMetadata(ctx context.Context, client HTTPDoer, origin, path string) ([]byte, int, error) {
	if client == nil || (path != "/healthz" && path != "/v2/client/identity") {
		return nil, 0, errors.New("invalid Hub metadata request")
	}
	target, err := joinOrigin(origin, path)
	if err != nil {
		return nil, 0, errors.New("invalid Hub origin")
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, target, nil)
	if err != nil {
		return nil, 0, errors.New("invalid Hub request")
	}
	request.Header.Set("Accept", "application/json")
	response, err := client.Do(request)
	if err != nil {
		return nil, 0, errors.New("Hub unavailable")
	}
	defer response.Body.Close()
	if response.Request != nil && response.Request.URL.String() != request.URL.String() {
		return nil, response.StatusCode, errors.New("Hub redirect rejected")
	}
	data, err := io.ReadAll(io.LimitReader(response.Body, maxMetadataBytes+1))
	if err != nil || len(data) > maxMetadataBytes {
		clear(data)
		return nil, response.StatusCode, errors.New("Hub metadata rejected")
	}
	return data, response.StatusCode, nil
}

func postAccountPacket(ctx context.Context, client HTTPDoer, origin, cardOrigin, operation string, packet []byte) ([]byte, int, error) {
	path, ok := accountRoutes[operation]
	if !ok || client == nil || len(packet) == 0 || len(packet) > wire.MaxPacketBytes {
		return nil, 0, errors.New("invalid Hub account request")
	}
	target, err := joinOrigin(origin, path)
	if err != nil {
		return nil, 0, errors.New("invalid Hub origin")
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, target, bytes.NewReader(packet))
	if err != nil {
		return nil, 0, errors.New("invalid Hub account request")
	}
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("Accept", "application/json")
	request.Header.Set("Origin", cardOrigin)
	response, err := client.Do(request)
	if err != nil {
		return nil, 0, errors.New("Hub unavailable")
	}
	defer response.Body.Close()
	if response.Request != nil && response.Request.URL.String() != request.URL.String() {
		return nil, response.StatusCode, errors.New("Hub redirect rejected")
	}
	data, readErr := io.ReadAll(io.LimitReader(response.Body, wire.MaxPacketBytes+1))
	if readErr != nil || len(data) > wire.MaxPacketBytes {
		clear(data)
		return nil, response.StatusCode, errors.New("Hub account response rejected")
	}
	if response.StatusCode != http.StatusOK {
		clear(data)
		if response.StatusCode == http.StatusForbidden || response.StatusCode == http.StatusTooManyRequests {
			return nil, response.StatusCode, errors.New("Hub account request rejected")
		}
		return nil, response.StatusCode, errors.New("Hub account service unavailable")
	}
	return data, response.StatusCode, nil
}

func verifyHealth(data []byte) (string, error) {
	defer clear(data)
	var value struct {
		Status            string `json:"status"`
		Service           string `json:"service"`
		Version           string `json:"version"`
		Stage             string `json:"stage"`
		Revision          string `json:"revision"`
		Dirty             bool   `json:"dirty"`
		SourceFingerprint string `json:"source_fingerprint"`
		CatalogSHA256     string `json:"catalog_sha256"`
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&value); err != nil || value.Status != "ok" || value.Service == "" || len(value.Service) > 64 {
		return "", errors.New("Hub health check failed")
	}
	if decoder.Decode(new(any)) != io.EOF {
		return "", errors.New("Hub health check failed")
	}
	return value.Service, nil
}

func joinOrigin(origin, path string) (string, error) {
	u, err := url.Parse(origin)
	if err != nil || u.Host == "" || u.Path != "" || (u.Scheme != "https" && u.Scheme != "http") || !strings.HasPrefix(path, "/") {
		return "", errors.New("invalid origin")
	}
	return origin + path, nil
}
