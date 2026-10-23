package appcore

import (
	"context"
	"io"
	"net/http"
	"strings"

	wire "github.com/cicada-ai/cicada/internal/hubaccountwire"
)

func (c *nativeController) discoverPairAvailability(ctx context.Context) error {
	c.pairDiscoveryTried, c.pairAvailable = true, false
	if !c.connected || c.httpClient() == nil {
		return ErrInvalidAction
	}
	target, err := joinOrigin(c.connection.Origin, wire.NativePairCapabilitiesPath)
	if err != nil {
		return err
	}
	r, err := http.NewRequestWithContext(ctx, http.MethodGet, target, nil)
	if err != nil {
		return err
	}
	r.Header.Set("Accept", "application/json")
	r.Header.Set("Cache-Control", "no-store")
	response, err := c.httpClient().Do(r)
	if err != nil {
		return err
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK || response.Request != nil && response.Request.URL.String() != r.URL.String() {
		return wire.ErrInvalid
	}
	raw, err := io.ReadAll(io.LimitReader(response.Body, wire.MaxNativePairCapabilitiesBytes+1))
	defer clear(raw)
	if err != nil || len(raw) > wire.MaxNativePairCapabilitiesBytes {
		return wire.ErrInvalid
	}
	capabilities, err := wire.DecodeNativePairCapabilities(raw)
	if err != nil {
		return err
	}
	if strings.HasPrefix(c.connection.Origin, "https://") {
		if capabilities.TransportPolicy != wire.AppNodeTransportHTTPS {
			return wire.ErrInvalid
		}
	} else if !c.cfg.AllowLoopbackHTTP || !c.connection.AllowLoopbackHTTP || capabilities.TransportPolicy != wire.AppNodeTransportLoopbackTest {
		return wire.ErrInvalid
	}
	c.pairAvailable = true
	return nil
}
