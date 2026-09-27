package control

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"time"
)

func validateResolvedHost(ctx context.Context, target *url.URL) error {
	if ip := net.ParseIP(target.Hostname()); ip != nil {
		if privateAddress(ip) {
			return errors.New("external action url cannot target a private or local IP")
		}
		return nil
	}
	addresses, err := net.DefaultResolver.LookupIPAddr(ctx, target.Hostname())
	if err != nil {
		return fmt.Errorf("resolve external action host: %w", err)
	}
	if len(addresses) == 0 {
		return errors.New("external action host has no addresses")
	}
	for _, address := range addresses {
		if privateAddress(address.IP) {
			return errors.New("external action host resolves to a private or local IP")
		}
	}
	return nil
}

func privateAddress(ip net.IP) bool {
	return ip.IsPrivate() || ip.IsLoopback() || ip.IsLinkLocalUnicast() ||
		ip.IsUnspecified() || ip.IsMulticast()
}

func safeExternalHTTPClient() *http.Client {
	transport := &http.Transport{Proxy: nil, DisableKeepAlives: true, DialContext: safeExternalDialContext}
	return &http.Client{
		Timeout: externalRequestTimeout, Transport: transport,
		CheckRedirect: func(request *http.Request, _ []*http.Request) error {
			if _, err := validateExternalURL(request.URL.String()); err != nil {
				return err
			}
			if request.Response != nil && request.Response.Request != nil &&
				request.Response.Request.URL.Scheme == "https" && request.URL.Scheme != "https" {
				return errors.New("external action cannot downgrade HTTPS")
			}
			return validateResolvedHost(request.Context(), request.URL)
		},
	}
}

func safeExternalDialContext(ctx context.Context, network, address string) (net.Conn, error) {
	host, port, err := net.SplitHostPort(address)
	if err != nil {
		return nil, fmt.Errorf("split external action address: %w", err)
	}
	addresses, err := net.DefaultResolver.LookupIPAddr(ctx, host)
	if err != nil {
		return nil, fmt.Errorf("resolve external action address: %w", err)
	}
	dialer := &net.Dialer{Timeout: 5 * time.Second, KeepAlive: 30 * time.Second}
	var lastErr error
	for _, candidate := range addresses {
		if privateAddress(candidate.IP) {
			return nil, errors.New("external action address resolves to a private or local IP")
		}
		connection, dialErr := dialer.DialContext(ctx, network, net.JoinHostPort(candidate.IP.String(), port))
		if dialErr == nil {
			return connection, nil
		}
		lastErr = dialErr
	}
	if lastErr == nil {
		lastErr = errors.New("external action address has no public addresses")
	}
	return nil, lastErr
}
