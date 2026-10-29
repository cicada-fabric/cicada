package store

import (
	"database/sql"
	"encoding/json"

	"github.com/cicada-ai/cicada/internal/e2ee"
	wire "github.com/cicada-ai/cicada/internal/hubaccountwire"
)

func appNodeScopedWriterLock(tx *sql.Tx) error {
	r, err := tx.Exec(`UPDATE hub_app_node_scoped_guard_v1 SET touched=touched WHERE id=1`)
	if err != nil {
		return err
	}
	if n, err := r.RowsAffected(); err != nil || n != 1 {
		return ErrHubAccountRejected
	}
	return nil
}

func appNodeScopedOneRow(result sql.Result, err error) error {
	if err != nil {
		return err
	}
	if n, err := result.RowsAffected(); err != nil || n != 1 {
		return ErrHubAccountRejected
	}
	return nil
}

// Reuse the independently authenticated original account/Owner/App actor. Node
// selection adds a namespace, never a new identity, source flag or epoch.
func appNodeScopedActorFromBase(a *hubAppNodeActor, node string) *hubAppNodeScopedActor {
	s := a.scope
	return &hubAppNodeScopedActor{scope: e2ee.OwnerAppNodeScopedScope{
		Version: 2, AuthorityNodeID: node, Origin: s.Origin, HubID: s.HubID, HubFingerprint: s.HubFingerprint,
		AccountID: s.AccountID, AccountSessionID: s.AccountSessionID, AccountSessionExpiresAt: s.AccountSessionExpiresAt,
		OwnerID: s.OwnerID, OwnerPublic: s.OwnerPublic, OwnerKeyVersion: s.OwnerKeyVersion,
		DeviceID: s.DeviceID, DevicePublic: s.DevicePublic, AccountEpoch: s.AccountEpoch, DeviceEpoch: s.DeviceEpoch,
		ClientSessionEpoch: s.ClientSessionEpoch, TransportPolicy: s.TransportPolicy,
	}, counters: a.counters, root: a.root, source: a.source, session: a.session}
}

// This projection is used only by the existing account-session lookup. It
// does not authenticate a proof or convert a scoped grant into legacy rights.
func appNodeScopedIdentity(s e2ee.OwnerAppNodeScopedScope) e2ee.OwnerAppNodeScope {
	return e2ee.OwnerAppNodeScope{Version: 1, Origin: s.Origin, HubID: s.HubID, HubFingerprint: s.HubFingerprint,
		AccountID: s.AccountID, AccountSessionID: s.AccountSessionID, AccountSessionExpiresAt: s.AccountSessionExpiresAt,
		OwnerID: s.OwnerID, OwnerPublic: s.OwnerPublic, OwnerKeyVersion: s.OwnerKeyVersion,
		DeviceID: s.DeviceID, DevicePublic: s.DevicePublic, AccountEpoch: s.AccountEpoch, DeviceEpoch: s.DeviceEpoch,
		ClientSessionEpoch: s.ClientSessionEpoch, TransportPolicy: s.TransportPolicy}
}

func appNodeScopedGrantNode(tx *sql.Tx, owner, device, grant string) (string, error) {
	var node string
	err := tx.QueryRow(`SELECT authority_node_id FROM hub_app_node_grants_v1 WHERE authority_kind='NODE_V1' AND owner_id=? AND device_id=? AND grant_id=?`, owner, device, grant).Scan(&node)
	if err != nil || node == "" {
		return "", ErrHubAccountRejected
	}
	return node, nil
}

func appNodeScopedInputNode(tx *sql.Tx, in HubAppNodeScopedAuthorityInput) (string, error) {
	var node string
	switch q := in.Body.(type) {
	case wire.AppNodeScopedPrepare:
		var p e2ee.OwnerAppNodeScopedPreview
		if json.Unmarshal(q.OwnerIntent, &p) != nil {
			return "", ErrHubAccountRejected
		}
		node = p.Claims.Scope.AuthorityNodeID
	case wire.AppNodeScopedComplete:
		var p e2ee.OwnerAppNodeScopedGrant
		if json.Unmarshal(q.OwnerGrant, &p) != nil {
			return "", ErrHubAccountRejected
		}
		node = p.Claims.Scope.AuthorityNodeID
	case wire.AppNodeScopedStatus:
		node = q.Target.NodeID
		if node == "" {
			digest, err := wire.AppNodeCodeDigest(in.Hub.HubID, q.Target.CandidateCode)
			if err != nil {
				return "", ErrHubAccountRejected
			}
			if err := tx.QueryRow(`SELECT node_id FROM node_control_key_requests_v1 WHERE hub_id=? AND code_digest=?`, in.Hub.HubID, digest).Scan(&node); err != nil {
				return "", err
			}
		}
	case wire.AppNodeScopedCancel:
		node = q.AuthorityNodeID
	case wire.AppNodeScopedReconcile:
		node = q.AuthorityNodeID
	default:
		return "", ErrHubAccountRejected
	}
	if node == "" || node == "control-local" || node == "worker-local" {
		return "", ErrHubAccountRejected
	}
	return node, nil
}
