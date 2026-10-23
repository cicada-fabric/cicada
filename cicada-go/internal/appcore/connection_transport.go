package appcore

import (
	"encoding/json"
	"errors"
	"reflect"
	"time"

	"github.com/cicada-ai/cicada/internal/hubtransport"
	"github.com/cicada-ai/cicada/internal/pqtls"
)

const localTransportFormat = "cicada.native-app-transport.v1"

// TransportClientFactory is an App test boundary. Production uses the shared
// verified transport; no environment or global trust-store override is used.
type TransportClientFactory func(hubtransport.Descriptor, string, time.Duration) (HTTPDoer, error)

// localTransportRecord contains only public trust material and reachability.
// It lives inside the original encrypted state, never in a new vault scope or
// a plaintext configuration file. Activation secrets remain in their existing
// encrypted account operation records and are not copied here.
type localTransportRecord struct {
	Format      string                  `json:"format"`
	Version     int                     `json:"version"`
	Descriptor  hubtransport.Descriptor `json:"descriptor"`
	DialAddress string                  `json:"dial_address"`
}

func validateLocalTransport(record *localTransportRecord, card HubConnectionCard) error {
	if record == nil {
		return nil
	}
	if record.Format != localTransportFormat || record.Version != 1 ||
		pqtls.ValidateIPDialAddress(record.DialAddress) != nil ||
		hubtransport.ValidateDescriptor(record.Descriptor, time.Time{}) != nil {
		return ErrInvalidCard
	}
	claims := record.Descriptor.Claims
	if claims.Origin != card.Origin || claims.Hub.HubID != card.HubID || claims.HubFingerprint != card.HubFingerprint {
		return ErrInvalidCard
	}
	return nil
}

func cloneLocalTransport(record *localTransportRecord) *localTransportRecord {
	if record == nil {
		return nil
	}
	// Public slices must not alias a caller's factory inputs or a saved record.
	raw, _ := json.Marshal(record)
	var copy localTransportRecord
	_ = json.Unmarshal(raw, &copy)
	return &copy
}

func validateLocalTransportReplacement(old, next *localTransportRecord, card HubConnectionCard) error {
	if validateLocalTransport(next, card) != nil || (old != nil && validateLocalTransport(old, card) != nil) {
		return ErrInvalidCard
	}
	if old == nil {
		return nil
	}
	// Transport rotation needs a separate controlled update protocol. A new
	// bootstrap cannot replace an enrolled profile's trust, even at a higher
	// epoch. Only the numeric locator may change under the existing claims.
	if next == nil || !reflect.DeepEqual(next.Descriptor.Claims, old.Descriptor.Claims) {
		return ErrInvalidCard
	}
	return nil
}

func (c *nativeController) useConnectionTransport(record *localTransportRecord, card HubConnectionCard) error {
	c.closeConnectionHTTP()
	c.directConnection = record != nil
	if record == nil {
		c.connectionTransport = nil
		c.transportState = ""
		return nil
	}
	if validateLocalTransport(record, card) != nil {
		c.transportState = HubTransportFailed
		return ErrInvalidCard
	}
	c.connectionTransport = cloneLocalTransport(record)
	factory := c.cfg.DirectHTTPFactory
	if factory == nil {
		factory = func(d hubtransport.Descriptor, address string, timeout time.Duration) (HTTPDoer, error) {
			return hubtransport.NewHTTPClient(d, address, timeout)
		}
	}
	client, err := factory(cloneLocalTransport(record).Descriptor, record.DialAddress, 20*time.Second)
	if err != nil || client == nil {
		if pool, ok := client.(interface{ CloseIdleConnections() }); ok {
			pool.CloseIdleConnections()
		}
		c.transportState = HubTransportFailed
		return ErrInvalidCard
	}
	c.connectionHTTP, c.transportState = client, HubTransportVerifying
	return nil
}

func (c *nativeController) connectionAddress() string {
	if c.connectionTransport == nil {
		return ""
	}
	return c.connectionTransport.DialAddress
}

func (c *nativeController) failConnectionTransport(code string) error {
	c.connected = false
	if c.vault != nil && c.cfg.DiscoverVaults != nil {
		c.profileRecoveryRequired = true
	}
	if c.directConnection {
		c.transportState = HubTransportFailed
		c.closeConnectionHTTP()
	}
	return c.fail(PhaseUnavailable, code, errors.New("Hub connection could not be verified"))
}
