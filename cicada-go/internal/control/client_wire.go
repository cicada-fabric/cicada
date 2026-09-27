package control

import (
	"errors"

	"github.com/cicada-ai/cicada/internal/clientwire"
	"github.com/cicada-ai/cicada/internal/e2ee"
	"github.com/cicada-ai/cicada/internal/store"
)

// ClientControlPublicIdentity is safe to publish in a Hub identity document.
// A remote Client must pin it through an independent enrollment ceremony;
// fetching it over an untrusted connection does not establish trust.
func (c *Control) ClientControlPublicIdentity() e2ee.PublicIdentity {
	if c == nil || c.clientIdentity == nil {
		return e2ee.PublicIdentity{}
	}
	return c.clientIdentity.Public()
}

func (c *Control) ClientHubID() (string, error) {
	if c == nil || c.store == nil {
		return "", errors.New("Client Hub identity is unavailable")
	}
	return c.store.GetClientHubID()
}

// RegisterClientDevice checks an independently trusted owner signature in
// Store. A management bearer or the submitted device public key cannot
// establish owner authorization.
func (c *Control) RegisterClientDevice(input store.RegisterClientDeviceInput) (*store.ClientDevice, error) {
	if c == nil || c.store == nil {
		return nil, errors.New("Client device registry is unavailable")
	}
	if err := c.ValidateClientOwnerScope(input.OwnerID); err != nil {
		return nil, err
	}
	return c.store.RegisterClientDeviceFromOwnerGrant(input)
}

func (c *Control) ClientDevice(ownerID, deviceID string) (*store.ClientDevice, error) {
	if c == nil || c.store == nil {
		return nil, errors.New("Client device registry is unavailable")
	}
	return c.store.GetClientDevice(ownerID, deviceID)
}

func (c *Control) ClientDevices(ownerID string) ([]store.ClientDevice, error) {
	if err := c.ValidateClientOwnerScope(ownerID); err != nil {
		return nil, err
	}
	return c.store.ListClientDevices(ownerID)
}

func (c *Control) RevokeClientDevice(ownerID, deviceID string, expectedVersion int64) (*store.ClientDevice, error) {
	if err := c.ValidateClientOwnerScope(ownerID); err != nil {
		return nil, err
	}
	return c.store.RevokeClientDevice(ownerID, deviceID, expectedVersion)
}

func (c *Control) AcceptClientControlRequest(input store.AcceptClientRequestInput) (*store.ClientRequestAcceptance, error) {
	if c == nil || c.store == nil {
		return nil, errors.New("Client request registry is unavailable")
	}
	if err := c.ValidateClientOwnerScope(input.OwnerID); err != nil {
		return nil, err
	}
	return c.store.AcceptClientRequest(input)
}

func (c *Control) AllocateClientControlResponseSequence(ownerID, deviceID string, epoch uint64) (uint64, error) {
	if c == nil || c.store == nil {
		return 0, errors.New("Client request registry is unavailable")
	}
	return c.store.AllocateClientResponseSequence(ownerID, deviceID, epoch)
}

func (c *Control) CompleteClientControlRequest(ownerID, deviceID, operationID string, packet []byte) (*store.ClientRequest, error) {
	if c == nil || c.store == nil {
		return nil, errors.New("Client request registry is unavailable")
	}
	return c.store.CompleteClientRequestWithSealedResponse(ownerID, deviceID, operationID, packet)
}

func (c *Control) FailClientControlRequest(ownerID, deviceID, operationID string) (*store.ClientRequest, error) {
	if c == nil || c.store == nil {
		return nil, errors.New("Client request registry is unavailable")
	}
	return c.store.UpdateClientRequestStatus(ownerID, deviceID, operationID, store.ClientRequestFailed)
}

func (c *Control) ClientApproval(ownerID, approvalID string) (*store.Approval, error) {
	if err := c.ValidateClientOwnerScope(ownerID); err != nil {
		return nil, err
	}
	return c.store.GetApproval(approvalID)
}

// OpenClientControlPacket only authenticates the cryptographic packet. The
// caller must load the device key and Binding from trusted durable state,
// atomically record replay identity, then authorize the operation.
func (c *Control) OpenClientControlPacket(device e2ee.PublicIdentity, binding clientwire.Binding, packet []byte) (clientwire.Opened, error) {
	if c == nil || c.clientIdentity == nil {
		return clientwire.Opened{}, errors.New("Client-Control identity is unavailable")
	}
	return clientwire.OpenRequest(c.clientIdentity, device, binding, packet)
}

func (c *Control) SealClientControlResponse(device e2ee.PublicIdentity, binding clientwire.Binding, route clientwire.Route, body []byte) ([]byte, error) {
	if c == nil || c.clientIdentity == nil {
		return nil, errors.New("Client-Control identity is unavailable")
	}
	return clientwire.SealResponse(c.clientIdentity, device, binding, route, body)
}
