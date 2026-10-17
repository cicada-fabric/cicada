package appcore

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net/http"
	"time"

	wire "github.com/cicada-ai/cicada/internal/hubaccountwire"
)

func (c *nativeController) postPairPacket(ctx context.Context, request *pairRequestRecord) ([]byte, error) {
	if request == nil || c.cfg.HTTP == nil || len(request.Packet) == 0 {
		return nil, ErrInvalidAction
	}
	path := wire.NativePairHTTPPath(request.Route.Operation)
	if path == "" {
		return nil, ErrInvalidAction
	}
	target, err := joinOrigin(c.connection.Origin, path)
	if err != nil {
		return nil, err
	}
	callCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	r, err := http.NewRequestWithContext(callCtx, http.MethodPost, target, bytes.NewReader(request.Packet))
	if err != nil {
		return nil, err
	}
	r.Header.Set("Content-Type", "application/json")
	r.Header.Set("Accept", "application/json")
	r.Header.Set("Origin", c.connection.Origin)
	r.Header.Set("Cache-Control", "no-store")
	response, err := c.cfg.HTTP.Do(r)
	if err != nil {
		return nil, errors.New("native pair request outcome is unknown")
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK || response.Request != nil && response.Request.URL.String() != r.URL.String() {
		return nil, errors.New("native pair request outcome is unknown")
	}
	limit := wire.MaxNativePairReceiptBytes
	if request.Route.Operation == wire.OperationNativePairReconcile {
		limit = wire.MaxNativePairReconcilePacketBytes
	}
	raw, err := io.ReadAll(io.LimitReader(response.Body, int64(limit)+1))
	if err != nil || len(raw) > limit {
		clear(raw)
		return nil, errors.New("native pair response is unconfirmed")
	}
	return raw, nil
}

func (c *nativeController) failPair(code string, err error) error {
	c.pairError = code
	return c.fail(PhaseUnavailable, code, err)
}

func (c *nativeController) failPairStorage(err error) error {
	c.profileRecoveryRequired = c.cfg.DiscoverVaults != nil || len(c.profiles) != 0
	return c.failStorage("APP_PAIR_COMMIT_FAILED", err)
}
