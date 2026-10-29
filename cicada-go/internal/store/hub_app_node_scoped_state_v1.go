package store

import (
	"database/sql"
	"encoding/json"
	"errors"
	"reflect"
	"time"

	"github.com/cicada-ai/cicada/internal/e2ee"
	wire "github.com/cicada-ai/cicada/internal/hubaccountwire"
)

type hubAppNodeScopedActor struct {
	scope    e2ee.OwnerAppNodeScopedScope
	counters wire.AppNodeClientCounters
	root     string
	source   bool
	session  *HubAccountSession
}
type hubAppNodeScopedHead struct {
	version            uint64
	latest, provenance string
}
type hubAppNodeScopedGrant struct {
	claims                    e2ee.OwnerAppNodeScopedGrantClaims
	state, reason, provenance string
	remaining                 uint64
}

// Diagnostic actor lookup requires the exact previously registered App key;
// source=true additionally requires permanent completed N2 provenance and all
// current security guards. Password/session possession alone is insufficient.
func appNodeScopedHead(tx *sql.Tx, owner, device, node string) (hubAppNodeScopedHead, error) {
	var h hubAppNodeScopedHead
	err := tx.QueryRow(`SELECT head_version,latest_grant_id,provenance_id FROM hub_app_node_scoped_heads_v1 WHERE owner_id=? AND device_id=? AND authority_node_id=?`, owner, device, node).Scan(&h.version, &h.latest, &h.provenance)
	if errors.Is(err, sql.ErrNoRows) {
		err = nil
	}
	return h, err
}
func appNodeScopedGrant(tx *sql.Tx, owner, device, node, id string) (*hubAppNodeScopedGrant, error) {
	var g hubAppNodeScopedGrant
	var raw string
	err := tx.QueryRow(`SELECT claims_json,state,reason,remaining,provenance_id FROM hub_app_node_grants_v1 WHERE authority_kind='NODE_V1' AND owner_id=? AND device_id=? AND authority_node_id=? AND grant_id=?`, owner, device, node, id).Scan(&raw, &g.state, &g.reason, &g.remaining, &g.provenance)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	if json.Unmarshal([]byte(raw), &g.claims) != nil {
		return nil, ErrHubAccountRejected
	}
	if g.claims.Scope.Version != 2 || g.claims.Scope.AuthorityNodeID != node || g.claims.Scope.OwnerID != owner || g.claims.Scope.DeviceID != device || g.claims.GrantID != id {
		return nil, ErrHubAccountRejected
	}
	return &g, nil
}

func appNodeScopedSameSecurity(a, b e2ee.OwnerAppNodeScopedScope) bool {
	a.HeadVersion, b.HeadVersion = 0, 0
	a.AccountSessionID, b.AccountSessionID = "", ""
	a.AccountSessionExpiresAt, b.AccountSessionExpiresAt = "", ""
	return reflect.DeepEqual(a, b)
}
func appNodeScopedScopeCurrent(a *hubAppNodeScopedActor, s e2ee.OwnerAppNodeScopedScope) bool {
	return a.source && a.session != nil && appNodeScopedSameSecurity(a.scope, s) && a.session.ID == s.AccountSessionID && a.session.ExpiresAt == s.AccountSessionExpiresAt
}

func appNodeScopedEffectiveState(tx *sql.Tx, a *hubAppNodeScopedActor, g *hubAppNodeScopedGrant, at time.Time) (string, string) {
	state, reason := g.state, g.reason
	if state != wire.AppNodeScopedPrepared && state != wire.AppNodeScopedActive {
		return state, reason
	}
	if !a.source || !appNodeScopedSameSecurity(a.scope, g.claims.Scope) {
		return wire.AppNodeScopedRevoked, "SECURITY_FENCE"
	}
	if session, e := appNodeSession(tx, appNodeScopedIdentity(g.claims.Scope), g.claims.Scope.AccountSessionID, at); e != nil || session.ExpiresAt != g.claims.Scope.AccountSessionExpiresAt {
		return wire.AppNodeScopedSessionEnded, "SESSION_ENDED"
	}
	if !appNodeBefore(at, g.claims.LeaseExpiresAt) || (state == wire.AppNodeScopedPrepared && (!appNodeBefore(at, g.claims.ProofExpiresAt) || (g.claims.Candidate != nil && !appNodeBefore(at, g.claims.Candidate.ExpiresAt)))) {
		return wire.AppNodeScopedExpired, "EXPIRED"
	}
	return state, reason
}

// Refresh only removes authority. It preserves the published head/provenance
// and never turns a terminal row into active authority after another login.
func appNodeScopedRefresh(tx *sql.Tx, a *hubAppNodeScopedActor, at time.Time) error {
	rows, err := tx.Query(`SELECT grant_id FROM hub_app_node_grants_v1 WHERE authority_kind='NODE_V1' AND authority_node_id=? AND owner_id=? AND device_id=? AND state IN('PREPARED','ACTIVE')`, a.scope.AuthorityNodeID, a.scope.OwnerID, a.scope.DeviceID)
	if err != nil {
		return err
	}
	var ids []string
	for rows.Next() {
		var id string
		if err = rows.Scan(&id); err != nil {
			break
		}
		ids = append(ids, id)
	}
	re := rows.Err()
	rows.Close()
	if err != nil {
		return err
	}
	if re != nil {
		return re
	}
	for _, id := range ids {
		g, e := appNodeScopedGrant(tx, a.scope.OwnerID, a.scope.DeviceID, a.scope.AuthorityNodeID, id)
		if e != nil {
			return e
		}
		state, reason := appNodeScopedEffectiveState(tx, a, g, at)
		if state != g.state {
			if _, e = tx.Exec(`UPDATE hub_app_node_grants_v1 SET state=?,reason=? WHERE grant_id=?`, state, reason, id); e != nil {
				return e
			}
		}
	}
	return nil
}

func appNodeScopedSnapshot(tx *sql.Tx, a *hubAppNodeScopedActor, id string, at time.Time) (wire.AppNodeScopedAuthoritySnapshot, error) {
	h, err := appNodeScopedHead(tx, a.scope.OwnerID, a.scope.DeviceID, a.scope.AuthorityNodeID)
	if err != nil {
		return wire.AppNodeScopedAuthoritySnapshot{}, err
	}
	s := wire.AppNodeScopedAuthoritySnapshot{Scope: a.scope, GrantID: id, State: wire.AppNodeScopedAbsent, CurrentHeadVersion: h.version, LatestGrantID: h.latest, ConfirmationProvenanceID: h.provenance, RootState: a.root, AllowedOperations: []string{}, LoginRequired: a.session == nil, Counters: a.counters}
	s.Scope.HeadVersion = h.version
	g, err := appNodeScopedGrant(tx, a.scope.OwnerID, a.scope.DeviceID, a.scope.AuthorityNodeID, id)
	if err != nil {
		return s, err
	}
	if g == nil {
		return s, nil
	}
	s.State, s.EndReason = appNodeScopedEffectiveState(tx, a, g, at)
	s.Profile, s.LeaseExpiresAt = g.claims.Profile, g.claims.LeaseExpiresAt
	// LoginRequired describes the bound login, independently of a finite
	// grant's lifecycle. A valid same-session terminal observation can close
	// obsolete App state without inventing a new login or restoring authority.
	s.LoginRequired = !appNodeScopedScopeCurrent(a, g.claims.Scope)
	if s.State == wire.AppNodeScopedActive && h.latest == id && h.version == g.claims.Scope.HeadVersion && appNodeScopedScopeCurrent(a, g.claims.Scope) && appNodeBefore(at, g.claims.LeaseExpiresAt) {
		s.Scope = g.claims.Scope
		s.RemainingConfirmations = g.remaining
		if g.remaining == 1 && g.claims.Profile == wire.AppNodeScopedProfileInitial {
			s.AllowedOperations = wire.AppNodeScopedAllowedOperations()
		}
	}
	return s, nil
}
