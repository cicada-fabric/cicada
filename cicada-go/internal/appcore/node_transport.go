package appcore

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net/http"
	"strings"

	wire "github.com/cicada-ai/cicada/internal/hubaccountwire"
)

// Availability is queried before any first secret POST or pending record.
// An unsigned discovery failure can prevent a new request, never settle an
// existing uncertain request or erase its original bytes.
func (c *nativeController) discoverNodeAvailability(ctx context.Context) error {
	c.nodeDiscoveryTried = true
	if !c.connected || c.device == nil || c.owner == nil || c.cfg.HTTP == nil {
		return ErrInvalidAction
	}
	target, err := joinOrigin(c.connection.Origin, wire.AppNodeCapabilitiesPath)
	if err != nil {
		return err
	}
	r, err := http.NewRequestWithContext(ctx, http.MethodGet, target, nil)
	if err != nil {
		return err
	}
	r.Header.Set("Accept", "application/json")
	r.Header.Set("Cache-Control", "no-store")
	response, err := c.cfg.HTTP.Do(r)
	if err != nil {
		c.nodeAvailable = false
		return errors.New("Node feature availability is unknown")
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK || (response.Request != nil && response.Request.URL.String() != r.URL.String()) {
		c.nodeAvailable = false
		return errors.New("Node feature is unavailable")
	}
	data, err := io.ReadAll(io.LimitReader(response.Body, wire.MaxAppNodeCapabilitiesBytes+1))
	defer clear(data)
	if err != nil || len(data) > wire.MaxAppNodeCapabilitiesBytes {
		c.nodeAvailable = false
		return wire.ErrInvalid
	}
	capabilities, err := wire.DecodeAppNodeCapabilities(data)
	if err != nil || !capabilities.Available {
		c.nodeAvailable = false
		return wire.ErrInvalid
	}
	if (strings.HasPrefix(c.connection.Origin, "https://") && capabilities.TransportPolicy != wire.AppNodeTransportHTTPS) ||
		(strings.HasPrefix(c.connection.Origin, "http://") && (!c.cfg.AllowLoopbackHTTP || !c.connection.AllowLoopbackHTTP || capabilities.TransportPolicy != wire.AppNodeTransportLoopbackTest)) {
		c.nodeAvailable = false
		return wire.ErrInvalid
	}
	c.nodeAvailable = true
	return nil
}

func (c *nativeController) postNodePacket(ctx context.Context, p *nodeOperation) ([]byte, error) {
	if p == nil || len(p.Request) == 0 || c.cfg.HTTP == nil {
		return nil, ErrInvalidAction
	}
	path := wire.AppNodeHTTPPath(p.Operation)
	if p.Kind == wire.AppNodeOriginalClient && p.Operation == "nodes.confirm" {
		path = "/v2/client/rpc"
	}
	if path == "" {
		return nil, ErrInvalidAction
	}
	target, err := joinOrigin(c.connection.Origin, path)
	if err != nil {
		return nil, err
	}
	r, err := http.NewRequestWithContext(ctx, http.MethodPost, target, bytes.NewReader(p.Request))
	if err != nil {
		return nil, err
	}
	r.Header.Set("Content-Type", "application/json")
	r.Header.Set("Accept", "application/json")
	r.Header.Set("Origin", c.connection.Origin)
	r.Header.Set("Cache-Control", "no-store")
	response, err := c.cfg.HTTP.Do(r)
	if err != nil {
		return nil, errors.New("Node request outcome is unknown")
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK || (response.Request != nil && response.Request.URL.String() != r.URL.String()) {
		return nil, errors.New("Node request outcome is unknown")
	}
	data, err := io.ReadAll(io.LimitReader(response.Body, wire.MaxPacketBytes+1))
	if err != nil || len(data) > wire.MaxPacketBytes {
		clear(data)
		return nil, errors.New("Node response is unconfirmed")
	}
	return data, nil
}

func (c *nativeController) nodeSession() wire.AppNodeSession {
	s := wire.AppNodeSession{Hub: c.hub, Origin: c.connection.Origin, AccountID: c.connection.AccountID, OwnerID: c.connection.OwnerID,
		DeviceID: c.state.DeviceID, AccountEpoch: c.state.ObservedAccountEpoch, DeviceEpoch: c.state.ObservedDeviceEpoch}
	if c.session != nil {
		s.AccountEpoch, s.DeviceEpoch, s.Token = c.session.AccountEpoch, c.session.DeviceEpoch, c.session.SessionToken
	}
	if s.AccountEpoch == 0 && c.node.Grant != nil {
		s.AccountEpoch = c.node.Grant.Claims.Scope.AccountEpoch
	}
	if s.DeviceEpoch == 0 && c.node.Grant != nil {
		s.DeviceEpoch = c.node.Grant.Claims.Scope.DeviceEpoch
	}
	return s
}
