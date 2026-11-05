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

// Current schemas do not silently promote an unclassified legacy native
// Endpoint. Zero-authority row creation is separate and grants no Group rights.
func threadCollaborationUnregisteredNativeTx(tx *sql.Tx, endpoint string) error {
	var present int
	if err := tx.QueryRow(`SELECT count(*) FROM sqlite_master WHERE type='table' AND name='thread_classifications_v1'`).Scan(&present); err != nil {
		return err
	}
	if present == 0 {
		return nil
	}
	var native bool
	err := tx.QueryRow(`SELECT native_session_id<>'' FROM fabric_endpoints WHERE id=?`, endpoint).Scan(&native)
	if errors.Is(err, sql.ErrNoRows) {
		return nil
	}
	if err != nil {
		return err
	}
	if native {
		return errors.New(wire.ThreadCollaborationErrorClassificationRequired)
	}
	return nil
}

func threadCollaborationEndpointActivationTx(tx *sql.Tx, endpoint, group string, at time.Time) error {
	r, err := endpointGroupsManagedTx(tx, endpoint)
	if err != nil {
		return err
	}
	if r == nil {
		return threadCollaborationUnregisteredNativeTx(tx, endpoint)
	}
	return threadCollaborationActivationTx(tx, r, group, at)
}
