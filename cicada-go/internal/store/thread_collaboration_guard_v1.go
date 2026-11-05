package store

import (
	"database/sql"
	"errors"
	wire "github.com/cicada-ai/cicada/internal/hubaccountwire"
	"time"
)

// Counts effective source relations, never raw active zero-authority joins.
// The resolver remains free of this Guard, avoiding Scope/Resolve recursion.
func threadCollaborationActivationTx(tx *sql.Tx, r *hubEndpointGroupsRegistration, group string, at time.Time) error {
	v, err := threadCollaborationScopeTx(tx, r, at)
	if err != nil {
		return err
	}
	switch v.State {
	case "CLASSIFICATION_REQUIRED":
		return errors.New(wire.ThreadCollaborationErrorClassificationRequired)
	case "NETWORK_CONFLICT":
		return errors.New(wire.ThreadCollaborationErrorNetworkConflict)
	case "GROUP_CONFLICT":
		return errors.New(wire.ThreadCollaborationErrorWorkerGroupLimit)
	case "CURRENT":
	default:
		return ErrNetworkPermission
	}
	if v.Classification == wire.ThreadClassificationWorker {
		card, _, _, err := endpointGroupsResolveTx(tx, r, group, at, false)
		if err != nil {
			return err
		}
		if card.State != "ACTIVE" && v.ActiveGroupCount >= 1 {
			return errors.New(wire.ThreadCollaborationErrorWorkerGroupLimit)
		}
	}
	return nil
}
