package store

import (
	"database/sql"
	"encoding/json"
	"reflect"
	"time"

	"github.com/cicada-ai/cicada/internal/e2ee"
	wire "github.com/cicada-ai/cicada/internal/hubaccountwire"
)

// Confirmation provenance is an exact committed Client request/effect record.
// Merely finding any active Node belonging to this Owner never adopts it.
func appNodeScopedProvenBinding(tx *sql.Tx, a *hubAppNodeScopedActor, provenance string, nodeControl e2ee.PublicIdentity) (*NodeControlKeyBinding, error) {
	var raw, grantID, requestID, operation, digest string
	var head uint64
	err := tx.QueryRow(`SELECT binding_json,grant_id,client_request_id,operation_id,request_digest,head_version FROM hub_app_node_provenance_v1 WHERE provenance_id=? AND owner_id=? AND device_id=?`, provenance, a.scope.OwnerID, a.scope.DeviceID).Scan(&raw, &grantID, &requestID, &operation, &digest, &head)
	var prior NodeControlKeyBinding
	if err != nil || json.Unmarshal([]byte(raw), &prior) != nil {
		return nil, ErrHubAccountRejected
	}
	g, err := appNodeScopedGrant(tx, a.scope.OwnerID, a.scope.DeviceID, a.scope.AuthorityNodeID, grantID)
	if err != nil || g == nil || g.provenance != provenance || g.remaining != 0 || g.claims.Profile != wire.AppNodeScopedProfileInitial || g.claims.Scope.HeadVersion != head || !appNodeScopedSameSecurity(a.scope, g.claims.Scope) || wire.ValidateAppNodeScopedConfirmationBinding(g.claims, appNodeBindingPublic(prior)) != nil {
		return nil, ErrHubAccountRejected
	}
	var savedOperation, savedDigest, status string
	var savedResponse, atomicResponse []byte
	// The old ledger's request/digest and the new provenance must both agree.
	if tx.QueryRow(`SELECT operation_id,ciphertext_digest,status,response_packet FROM client_device_requests_v2 WHERE id=? AND owner_id=? AND device_id=?`, requestID, a.scope.OwnerID, a.scope.DeviceID).Scan(&savedOperation, &savedDigest, &status, &savedResponse) != nil || savedOperation != operation || savedDigest != digest || status != ClientRequestCompleted {
		return nil, ErrHubAccountRejected
	}
	if tx.QueryRow(`SELECT response_packet FROM hub_app_node_operations_v1 WHERE owner_id=? AND device_id=? AND operation_id=? AND operation='nodes.confirm' AND kind='CLIENT_CONTROL' AND state='COMPLETED'`, a.scope.OwnerID, a.scope.DeviceID, operation).Scan(&atomicResponse) != nil || len(atomicResponse) == 0 || !reflect.DeepEqual(atomicResponse, savedResponse) {
		return nil, ErrHubAccountRejected
	}
	var credential string
	if tx.QueryRow(`SELECT node_credential_digest FROM node_owner_bindings_v2 WHERE id=? AND owner_id=? AND node_id=?`, prior.OwnerBindingID, a.scope.OwnerID, prior.NodeID).Scan(&credential) != nil {
		return nil, ErrHubAccountRejected
	}
	current, err := nodeControlCurrentBindingTx(tx, credential, prior.NodeID)
	if err != nil || !reflect.DeepEqual(appNodeBindingPublic(*current), appNodeBindingPublic(prior)) || !reflect.DeepEqual(current.HubPublicIdentity, nodeControl) || current.HubKeyVersion != 1 {
		return nil, ErrHubAccountRejected
	}
	return current, nil
}

func appNodeScopedObservation(tx *sql.Tx, a *hubAppNodeScopedActor, provenance string, nodeControl e2ee.PublicIdentity, at time.Time) (*wire.AppNodeObservation, error) {
	if provenance == "" {
		return nil, nil
	}
	b, err := appNodeScopedProvenBinding(tx, a, provenance, nodeControl)
	if err != nil {
		return nil, nil
	}
	n := &wire.AppNodeObservation{NodeID: b.NodeID, NodeName: b.NodeName, BindingID: b.OwnerBindingID, BindingVersion: b.BindingVersion, CredentialVersion: b.NodeCredentialVersion, NodeKeyID: b.NodeKeyID, NodeKeyFingerprint: b.NodeKeyFingerprint, NodeKeyEpoch: b.NodeKeyEpoch, BindingState: b.State, Authorized: true, Connectivity: "UNKNOWN", Stale: true, Source: "store.machines.last_seen", ObservedAt: appNodeStamp(at)}
	var last string
	if tx.QueryRow(`SELECT last_seen FROM machines WHERE id=? AND owner_id=?`, b.NodeID, a.scope.OwnerID).Scan(&last) != nil {
		return n, nil
	}
	heartbeat, err := time.Parse(time.RFC3339Nano, last)
	approved, ae := time.Parse(time.RFC3339Nano, b.ApprovedAt)
	if err != nil || ae != nil || heartbeat.Before(approved) || heartbeat.After(at) {
		return n, nil
	}
	n.Known = true
	n.LastHeartbeatAt = appNodeStamp(heartbeat)
	fresh := heartbeat.Add(wire.AppNodeObservationStaleAfter)
	n.FreshUntil = appNodeStamp(fresh)
	if at.Before(fresh) {
		n.Connectivity = "CONNECTED"
		n.Stale = false
	} else {
		n.Connectivity = "STALE"
	}
	return n, nil
}
