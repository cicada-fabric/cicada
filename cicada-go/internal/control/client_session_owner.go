package control

import (
	"errors"
	"fmt"
	"strings"

	"github.com/cicada-ai/cicada/internal/store"
)

// ValidateClientSessionOwner admits an independently enrolled human to the
// encrypted Client transport. It does not grant that human Control management
// authority: manager operations still call ValidateClientOwnerScope.
func (c *Control) ValidateClientSessionOwner(ownerID string) error {
	if c == nil || c.store == nil {
		return errors.New("Client session requires an initialized Hub")
	}
	ownerID = strings.TrimSpace(ownerID)
	if ownerID == "" {
		return fmt.Errorf("%w: missing Client owner", ErrPermissionDenied)
	}
	principal, err := c.store.GetPrincipal(ownerID)
	if err != nil {
		if errors.Is(err, store.ErrPrincipalNotFound) {
			return fmt.Errorf("%w: Client owner is not registered", ErrPermissionDenied)
		}
		return err
	}
	if principal.ID != ownerID || principal.OwnerID != ownerID ||
		principal.Kind != store.PrincipalKindHuman || principal.Status != store.PrincipalStatusActive ||
		(principal.TrustDomainID != "" && principal.TrustDomainID != ownerID) {
		return fmt.Errorf("%w: Client owner is not an active self-owned human", ErrPermissionDenied)
	}
	return nil
}
