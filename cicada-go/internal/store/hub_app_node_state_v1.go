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

type hubAppNodeActor struct {
	scope    e2ee.OwnerAppNodeScope
	counters wire.AppNodeClientCounters
	root     string
	source   bool
	session  *HubAccountSession
}
type hubAppNodeHead struct {
	version            uint64
	latest, provenance string
}
type hubAppNodeGrant struct {
	claims                    e2ee.OwnerAppNodeGrantClaims
	state, reason, provenance string
	remaining                 uint64
}

func appNodeStamp(at time.Time) string { return at.UTC().Format(time.RFC3339Nano) }
func appNodeBefore(at time.Time, end string) bool {
	t, e := time.Parse(time.RFC3339Nano, end)
	return e == nil && at.Before(t)
}

// Diagnostic actor lookup requires the exact previously registered App key;
// source=true additionally requires permanent completed N2 provenance and all
// current security guards. Password/session possession alone is insufficient.
func appNodeActor(tx *sql.Tx, hub wire.HubIdentity, deviceID string, public e2ee.PublicIdentity, token []byte, at time.Time) (*hubAppNodeActor, error) {
	setup, err := hubOwnerSetup(tx)
	if err != nil || setup == nil || setup.State != HubOwnerReady {
		return nil, ErrHubAccountRejected
	}
	var retainedHub string
	if tx.QueryRow(`SELECT hub_id FROM client_device_hub_config_v2 WHERE id=1`).Scan(&retainedHub) != nil || retainedHub != setup.HubID {
		return nil, ErrHubAccountRejected
	}
	epoch, err := accountEpoch(tx)
	if err != nil {
		return nil, err
	}
	var ad HubAccountDevice
	var raw string
	err = tx.QueryRow(`SELECT account_id,owner_id,device_id,public_identity_json,epoch,status FROM hub_account_devices_v1 WHERE account_id=? AND device_id=?`, setup.AccountID, deviceID).Scan(&ad.AccountID, &ad.OwnerID, &ad.DeviceID, &raw, &ad.Epoch, &ad.State)
	if err != nil || json.Unmarshal([]byte(raw), &ad.Public) != nil || !reflect.DeepEqual(ad.Public, public) || hub.HubID != setup.HubID {
		return nil, ErrHubAccountRejected
	}
	client, err := scanClientDevice(tx.QueryRow(clientDeviceSelect+` WHERE owner_id=? AND device_id=?`, setup.OwnerID, deviceID))
	if err != nil || !reflect.DeepEqual(client.Public, public) {
		return nil, ErrHubAccountRejected
	}
	key, err := scanOwnerApprovalKey(tx.QueryRow(`SELECT owner_id,key_id,public_identity_json,state,version,created_at,updated_at,revoked_at FROM owner_approval_keys_v2 WHERE owner_id=? AND key_id=?`, setup.OwnerID, client.OwnerKeyID))
	if err != nil {
		return nil, ErrHubAccountRejected
	}
	fp, err := wire.HubFingerprint(hub)
	if err != nil {
		return nil, err
	}
	policy := wire.AppNodeTransportHTTPS
	if setup.AllowLoopbackHTTP {
		policy = wire.AppNodeTransportLoopbackTest
	}
	a := &hubAppNodeActor{scope: e2ee.OwnerAppNodeScope{Version: 1, Origin: setup.Origin, HubID: hub.HubID, HubFingerprint: fp, AccountID: setup.AccountID, OwnerID: setup.OwnerID, OwnerPublic: key.Public, OwnerKeyVersion: uint64(key.Version), DeviceID: deviceID, DevicePublic: public, AccountEpoch: uint64(epoch), DeviceEpoch: uint64(ad.Epoch), ClientSessionEpoch: client.SessionEpoch, TransportPolicy: policy}, counters: wire.AppNodeClientCounters{SessionEpoch: client.SessionEpoch, LastRequestSequence: client.LastRequestSeq, NextResponseSequence: client.NextResponseSeq}, root: wire.RootUnavailableState}
	if key.State == OwnerApprovalKeyActive && activeSelfOwnedHuman(tx, setup.OwnerID) {
		a.root = wire.RootActiveState
	}
	var lease, activationID, leaseState, completed, state string
	var ae, de, activationEpoch int64
	err = tx.QueryRow(`SELECT binding_json,activation_id,state,account_epoch,device_epoch FROM hub_app_leases_v1 WHERE owner_id=? AND device_id=?`, setup.OwnerID, deviceID).Scan(&lease, &activationID, &leaseState, &ae, &de)
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		return nil, err
	}
	var n2 wire.ActivationBinding
	if err == nil && json.Unmarshal([]byte(lease), &n2) == nil {
		err = tx.QueryRow(`SELECT binding_json,state,epoch FROM hub_owner_activation_v1 WHERE activation_id=? AND account_id=? AND owner_id=?`, activationID, setup.AccountID, setup.OwnerID).Scan(&completed, &state, &activationEpoch)
		// N2 enrolls the App's Client key at key/session epoch 1. Its account
		// binding has no Client-epoch field; accepting a later reset here would
		// silently adopt changed security coordinates into the first N3 grant.
		a.source = err == nil && state == wire.ActivationCompleted && completed == lease && activationEpoch == epoch && leaseState == "ACTIVE" && ae == epoch && de == ad.Epoch && n2.AccountEpoch == uint64(epoch) && n2.DeviceEpoch == uint64(ad.Epoch) && n2.AccountID == setup.AccountID && n2.OwnerID == setup.OwnerID && n2.HubID == hub.HubID && n2.HubFingerprint == fp && n2.Origin == setup.Origin && n2.DeviceID == deviceID && reflect.DeepEqual(n2.OwnerPublic, key.Public) && reflect.DeepEqual(n2.DevicePublic, public) && ad.State == "ACTIVE" && client.State == ClientDeviceActive && client.KeyVersion == 1 && client.SessionEpoch == 1 && a.root == wire.RootActiveState
	}
	if len(token) > 0 {
		var id string
		if tx.QueryRow(`SELECT session_id FROM hub_account_sessions_v1 WHERE token_digest=?`, AccountDigest("session-token", token)).Scan(&id) == nil {
			if session, e := appNodeSession(tx, a.scope, id, at); e == nil {
				a.session = session
				a.scope.AccountSessionID = session.ID
				a.scope.AccountSessionExpiresAt = session.ExpiresAt
			}
		}
	}
	return a, nil
}

func appNodeSession(tx *sql.Tx, s e2ee.OwnerAppNodeScope, id string, at time.Time) (*HubAccountSession, error) {
	var v HubAccountSession
	err := tx.QueryRow(`SELECT session_id,account_id,owner_id,device_id,epoch,device_epoch,credential_version,token_digest,state,expires_at FROM hub_account_sessions_v1 WHERE session_id=?`, id).Scan(&v.ID, &v.AccountID, &v.OwnerID, &v.DeviceID, &v.Epoch, &v.DeviceEpoch, &v.CredentialVersion, &v.TokenDigest, &v.State, &v.ExpiresAt)
	var cv int64
	if err != nil || v.State != "ACTIVE" || v.AccountID != s.AccountID || v.OwnerID != s.OwnerID || v.DeviceID != s.DeviceID || uint64(v.Epoch) != s.AccountEpoch || uint64(v.DeviceEpoch) != s.DeviceEpoch || !appNodeBefore(at, v.ExpiresAt) || tx.QueryRow(`SELECT version FROM hub_account_credentials_v1 WHERE account_id=? AND owner_id=?`, s.AccountID, s.OwnerID).Scan(&cv) != nil || cv != v.CredentialVersion {
		return nil, ErrHubAccountRejected
	}
	return &v, nil
}

func appNodeHead(tx *sql.Tx, owner, device string) (hubAppNodeHead, error) {
	var h hubAppNodeHead
	err := tx.QueryRow(`SELECT head_version,latest_grant_id,provenance_id FROM hub_app_node_heads_v1 WHERE owner_id=? AND device_id=?`, owner, device).Scan(&h.version, &h.latest, &h.provenance)
	if errors.Is(err, sql.ErrNoRows) {
		err = nil
	}
	return h, err
}
func appNodeGrant(tx *sql.Tx, owner, device, id string) (*hubAppNodeGrant, error) {
	var g hubAppNodeGrant
	var raw string
	err := tx.QueryRow(`SELECT claims_json,state,reason,remaining,provenance_id FROM hub_app_node_grants_v1 WHERE owner_id=? AND device_id=? AND grant_id=?`, owner, device, id).Scan(&raw, &g.state, &g.reason, &g.remaining, &g.provenance)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	if json.Unmarshal([]byte(raw), &g.claims) != nil {
		return nil, ErrHubAccountRejected
	}
	return &g, nil
}

func appNodeSameSecurity(a, b e2ee.OwnerAppNodeScope) bool {
	a.HeadVersion, b.HeadVersion = 0, 0
	a.AccountSessionID, b.AccountSessionID = "", ""
	a.AccountSessionExpiresAt, b.AccountSessionExpiresAt = "", ""
	return reflect.DeepEqual(a, b)
}
func appNodeScopeCurrent(a *hubAppNodeActor, s e2ee.OwnerAppNodeScope) bool {
	return a.source && a.session != nil && appNodeSameSecurity(a.scope, s) && a.session.ID == s.AccountSessionID && a.session.ExpiresAt == s.AccountSessionExpiresAt
}

func appNodeEffectiveState(tx *sql.Tx, a *hubAppNodeActor, g *hubAppNodeGrant, at time.Time) (string, string) {
	state, reason := g.state, g.reason
	if state != wire.AppNodePrepared && state != wire.AppNodeActive {
		return state, reason
	}
	if !a.source || !appNodeSameSecurity(a.scope, g.claims.Scope) {
		return wire.AppNodeRevoked, "SECURITY_FENCE"
	}
	if session, e := appNodeSession(tx, g.claims.Scope, g.claims.Scope.AccountSessionID, at); e != nil || session.ExpiresAt != g.claims.Scope.AccountSessionExpiresAt {
		return wire.AppNodeSessionEnded, "SESSION_ENDED"
	}
	if !appNodeBefore(at, g.claims.LeaseExpiresAt) || (state == wire.AppNodePrepared && (!appNodeBefore(at, g.claims.ProofExpiresAt) || (g.claims.Candidate != nil && !appNodeBefore(at, g.claims.Candidate.ExpiresAt)))) {
		return wire.AppNodeExpired, "EXPIRED"
	}
	return state, reason
}

// Refresh only removes authority. It preserves the published head/provenance
// and never turns a terminal row into active authority after another login.
func appNodeRefresh(tx *sql.Tx, a *hubAppNodeActor, at time.Time) error {
	rows, err := tx.Query(`SELECT grant_id FROM hub_app_node_grants_v1 WHERE owner_id=? AND device_id=? AND state IN('PREPARED','ACTIVE')`, a.scope.OwnerID, a.scope.DeviceID)
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
		g, e := appNodeGrant(tx, a.scope.OwnerID, a.scope.DeviceID, id)
		if e != nil {
			return e
		}
		state, reason := appNodeEffectiveState(tx, a, g, at)
		if state != g.state {
			if _, e = tx.Exec(`UPDATE hub_app_node_grants_v1 SET state=?,reason=? WHERE grant_id=?`, state, reason, id); e != nil {
				return e
			}
		}
	}
	return nil
}

func appNodeSnapshot(tx *sql.Tx, a *hubAppNodeActor, id string, at time.Time) (wire.AppNodeAuthoritySnapshot, error) {
	h, err := appNodeHead(tx, a.scope.OwnerID, a.scope.DeviceID)
	if err != nil {
		return wire.AppNodeAuthoritySnapshot{}, err
	}
	s := wire.AppNodeAuthoritySnapshot{Scope: a.scope, GrantID: id, State: wire.AppNodeAbsent, CurrentHeadVersion: h.version, LatestGrantID: h.latest, ConfirmationProvenanceID: h.provenance, RootState: a.root, AllowedOperations: []string{}, LoginRequired: a.session == nil, Counters: a.counters}
	s.Scope.HeadVersion = h.version
	g, err := appNodeGrant(tx, a.scope.OwnerID, a.scope.DeviceID, id)
	if err != nil {
		return s, err
	}
	if g == nil {
		return s, nil
	}
	s.State, s.EndReason = appNodeEffectiveState(tx, a, g, at)
	s.Profile, s.LeaseExpiresAt = g.claims.Profile, g.claims.LeaseExpiresAt
	// LoginRequired describes the bound login, independently of a finite
	// grant's lifecycle. A valid same-session terminal observation can close
	// obsolete App state without inventing a new login or restoring authority.
	s.LoginRequired = !appNodeScopeCurrent(a, g.claims.Scope)
	if s.State == wire.AppNodeActive && h.latest == id && h.version == g.claims.Scope.HeadVersion && appNodeScopeCurrent(a, g.claims.Scope) && appNodeBefore(at, g.claims.LeaseExpiresAt) {
		s.Scope = g.claims.Scope
		s.RemainingConfirmations = g.remaining
		if g.remaining == 1 && g.claims.Profile == wire.AppNodeProfileInitial {
			s.AllowedOperations = wire.AppNodeAllowedOperations()
		}
	}
	return s, nil
}
