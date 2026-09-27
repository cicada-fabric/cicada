package control

import (
	"errors"
	"strings"

	"github.com/cicada-ai/cicada/internal/store"
)

// ManagementEndpointCards is the operator panel's read-only projection of
// explicitly joined v2 Endpoints. It never goes through the legacy global
// Directory or grants the management bearer a Fabric sending identity.
func (c *Control) ManagementEndpointCards(input EndpointListInput) ([]NetworkCard, error) {
	if c == nil || c.store == nil {
		return nil, errors.New("Endpoint management projection is unavailable")
	}
	ownerID := c.Identity().ID
	endpoints, err := c.store.ListEndpointsV2(store.EndpointV2Filter{
		OwnerID: ownerID, Status: input.Status, NodeID: input.MachineID,
		Harness: input.Harness, MigrationState: store.EndpointMigrationReady,
		Limit: input.Limit,
	})
	if err != nil {
		return nil, err
	}
	cards := make([]NetworkCard, 0, len(endpoints))
	for index := range endpoints {
		endpoint := endpoints[index]
		c.decorateEndpoint(&endpoint)
		cards = append(cards, *c.networkCard(endpoint))
	}
	return cards, nil
}

func (c *Control) ManagementEndpointCard(id string) (*NetworkCard, error) {
	if c == nil || c.store == nil {
		return nil, errors.New("Endpoint management projection is unavailable")
	}
	id = strings.TrimSpace(id)
	if id == "" {
		return nil, store.ErrEndpointNotFound
	}
	endpoint, err := c.store.GetEndpointV2(id)
	if err != nil {
		return nil, err
	}
	if endpoint.MigrationState != store.EndpointMigrationReady || endpoint.PrincipalID == "" {
		return nil, store.ErrEndpointNotFound
	}
	principal, err := c.store.GetPrincipal(endpoint.PrincipalID)
	if err != nil || principal == nil || principal.OwnerID != c.Identity().ID ||
		principal.Status != store.PrincipalStatusActive {
		return nil, store.ErrEndpointNotFound
	}
	c.decorateEndpoint(endpoint)
	return c.networkCard(*endpoint), nil
}
