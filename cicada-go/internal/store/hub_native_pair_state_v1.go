package store

import (
	"database/sql"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"reflect"
	"time"

	"github.com/cicada-ai/cicada/internal/e2ee"
	wire "github.com/cicada-ai/cicada/internal/hubaccountwire"
)

type HubNativePairInput struct {
	Hub               wire.HubIdentity
	NodeControlPublic e2ee.PublicIdentity
	Device            e2ee.PublicIdentity
	Packet            []byte
	Body              any
	At                time.Time
	Now               func() time.Time
	Original          *HubNativePairInput
	OriginalSeal      HubNativePairSeal
}
type HubNativePairSeal func(any) ([]byte, error)

type hubNativePair struct {
	id, hub, account, owner, device, node, network, group                    string
	scope                                                                    e2ee.OwnerNativePairScope
	bootstrap                                                                e2ee.NativePairBootstrapClaims
	bootstrapProof                                                           []byte
	state                                                                    wire.NativePairState
	revision                                                                 uint64
	planID, prepareID, proofExpires, joinUntil, peerExpires, created, reason string
}

func nativePairFields(body any) (c wire.NativePairRequestContext, token, proof []byte, op, pair string, err error) {
	var v wire.NativePairBootstrapPrepare
	switch b := body.(type) {
	case wire.NativePairBootstrapPrepare:
		v = b
		op = wire.OperationNativePairBootstrapPrepare
	case wire.NativePairBootstrapComplete:
		v = wire.NativePairBootstrapPrepare(b)
		op = wire.OperationNativePairBootstrapComplete
	case wire.NativePairConsentPrepare:
		v = wire.NativePairBootstrapPrepare(b)
		op = wire.OperationNativePairConsentPrepare
	case wire.NativePairSlotReject:
		v = wire.NativePairBootstrapPrepare(b)
		op = wire.OperationNativePairSlotReject
	case wire.NativePairRevoke:
		v = wire.NativePairBootstrapPrepare(b)
		op = wire.OperationNativePairRevoke
	case wire.NativePairConsentComplete:
		v = wire.NativePairBootstrapPrepare{Format: b.Format, Context: b.Context, SessionToken: b.SessionToken, OwnerProof: b.OwnerProof}
		op = wire.OperationNativePairConsentComplete
	case wire.NativePairStatusRequest:
		return b.Context, b.SessionToken, nil, wire.OperationNativePairStatus, b.PairID, nil
	case wire.NativePairReconcileRequest:
		return b.Context, nil, nil, wire.OperationNativePairReconcile, b.PairID, nil
	default:
		return c, nil, nil, "", "", ErrHubAccountRejected
	}
	var p e2ee.OwnerNativePairProof
	if json.Unmarshal(v.OwnerProof, &p) != nil {
		return c, nil, nil, "", "", ErrHubAccountRejected
	}
	switch p.Claims.Purpose {
	case e2ee.OwnerNativePairBootstrapCommit:
		if p.Claims.Bootstrap != nil {
			pair = p.Claims.Bootstrap.PairID
		}
	case e2ee.OwnerNativePairConsentPreview, e2ee.OwnerNativePairSlotConsent:
		if p.Claims.Consent != nil {
			pair = p.Claims.Consent.PairID
		}
	case e2ee.OwnerNativePairSlotReject:
		if p.Claims.Reject != nil {
			pair = p.Claims.Reject.PairID
		}
	case e2ee.OwnerNativePairRevoke:
		if p.Claims.Revoke != nil {
			pair = p.Claims.Revoke.PairID
		}
	}
	return v.Context, v.SessionToken, v.OwnerProof, op, pair, nil
}

func nativePairInput(in HubNativePairInput) (wire.NativePairRequestContext, []byte, []byte, string, string, error) {
	c, token, proof, op, pair, err := nativePairFields(in.Body)
	if err != nil || in.At.IsZero() {
		return c, nil, nil, "", "", ErrHubAccountRejected
	}
	p, err := wire.PreflightRequest(in.Packet, op)
	_, route, re := wire.RequestRoute(in.Hub, c.OwnerID, c.DeviceID, c.RequestID, op, wire.HandshakeEpoch, in.Device)
	if err != nil || re != nil || p.Packet.Route != route || !reflect.DeepEqual(p.SenderPublicIdentity, in.Device) || c.HubID != in.Hub.HubID || len(c.ClientNonce) != wire.NonceBytes {
		return c, nil, nil, "", "", ErrHubAccountRejected
	}
	return c, token, proof, op, pair, nil
}

func readNativePair(tx *sql.Tx, id string) (*hubNativePair, error) {
	var p hubNativePair
	var scope, bootstrap string
	err := tx.QueryRow(`SELECT pair_id,hub_id,account_id,owner_id,device_id,node_id,network_id,group_id,scope_json,bootstrap_json,bootstrap_owner_proof,state,control_revision,plan_id,prepare_operation_id,proof_expires_at,join_until,peer_expires_at,created_at,terminal_reason FROM hub_native_pairs_v1 WHERE pair_id=?`, id).Scan(&p.id, &p.hub, &p.account, &p.owner, &p.device, &p.node, &p.network, &p.group, &scope, &bootstrap, &p.bootstrapProof, &p.state, &p.revision, &p.planID, &p.prepareID, &p.proofExpires, &p.joinUntil, &p.peerExpires, &p.created, &p.reason)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	if json.Unmarshal([]byte(scope), &p.scope) != nil || json.Unmarshal([]byte(bootstrap), &p.bootstrap) != nil {
		return nil, ErrHubAccountRejected
	}
	return &p, nil
}

// The N3 confirmation receipt is permanent provenance, not a renewable N3
// permission. Labels may change without changing the authority coordinates.
func nativePairProvenNode(tx *sql.Tx, a *hubAppNodeActor, known e2ee.OwnerAppNodeBinding, nodeControl e2ee.PublicIdentity) (*NodeControlKeyBinding, error) {
	var provenance, raw, grantID, clientRequest, operation, digest string
	var head uint64
	err := tx.QueryRow(`SELECT provenance_id,binding_json,grant_id,client_request_id,operation_id,request_digest,head_version FROM hub_app_node_provenance_v1 WHERE owner_id=? AND device_id=? AND json_extract(binding_json,'$.owner_binding_id')=? ORDER BY rowid DESC LIMIT 1`, a.scope.OwnerID, a.scope.DeviceID, known.OwnerBindingID).Scan(&provenance, &raw, &grantID, &clientRequest, &operation, &digest, &head)
	var prior NodeControlKeyBinding
	if err != nil || json.Unmarshal([]byte(raw), &prior) != nil {
		return nil, ErrHubAccountRejected
	}
	g, err := appNodeGrant(tx, a.scope.OwnerID, a.scope.DeviceID, grantID)
	if err != nil || g == nil || g.provenance != provenance || g.remaining != 0 || g.claims.Profile != wire.AppNodeProfileInitial || g.claims.Scope.HeadVersion != head || !appNodeSameSecurity(a.scope, g.claims.Scope) || wire.ValidateAppNodeConfirmationBinding(g.claims, appNodeBindingPublic(prior)) != nil {
		return nil, ErrHubAccountRejected
	}
	var savedOperation, savedDigest, state string
	var oldReceipt, atomicReceipt []byte
	if tx.QueryRow(`SELECT operation_id,ciphertext_digest,status,response_packet FROM client_device_requests_v2 WHERE id=? AND owner_id=? AND device_id=?`, clientRequest, a.scope.OwnerID, a.scope.DeviceID).Scan(&savedOperation, &savedDigest, &state, &oldReceipt) != nil || savedOperation != operation || savedDigest != digest || state != ClientRequestCompleted {
		return nil, ErrHubAccountRejected
	}
	if tx.QueryRow(`SELECT response_packet FROM hub_app_node_operations_v1 WHERE owner_id=? AND device_id=? AND operation_id=? AND operation='nodes.confirm' AND kind='CLIENT_CONTROL' AND state='COMPLETED'`, a.scope.OwnerID, a.scope.DeviceID, operation).Scan(&atomicReceipt) != nil || len(atomicReceipt) == 0 || !reflect.DeepEqual(oldReceipt, atomicReceipt) {
		return nil, ErrHubAccountRejected
	}
	var credential string
	if tx.QueryRow(`SELECT node_credential_digest FROM node_owner_bindings_v2 WHERE id=? AND owner_id=? AND node_id=?`, known.OwnerBindingID, a.scope.OwnerID, known.NodeID).Scan(&credential) != nil {
		return nil, ErrHubAccountRejected
	}
	current, err := nodeControlCurrentBindingTx(tx, credential, known.NodeID)
	if err != nil || !reflect.DeepEqual(current.HubPublicIdentity, nodeControl) || current.HubKeyVersion != 1 {
		return nil, ErrHubAccountRejected
	}
	past, live, wanted := appNodeBindingPublic(prior), appNodeBindingPublic(*current), known
	past.NodeName, live.NodeName, wanted.NodeName = "", "", ""
	if !reflect.DeepEqual(past, live) || !reflect.DeepEqual(live, wanted) {
		return nil, ErrHubAccountRejected
	}
	return current, nil
}

func nativePairCurrentScope(tx *sql.Tx, a *hubAppNodeActor, known e2ee.OwnerAppNodeBinding, hub wire.HubIdentity, nodeControl e2ee.PublicIdentity) (e2ee.OwnerNativePairScope, error) {
	var out e2ee.OwnerNativePairScope
	if !a.source || a.session == nil {
		return out, ErrHubAccountRejected
	}
	b, err := nativePairProvenNode(tx, a, known, nodeControl)
	if err != nil {
		return out, err
	}
	credential, err := base64.RawURLEncoding.DecodeString(b.CredentialDigest)
	if err != nil || len(credential) != 32 || base64.RawURLEncoding.EncodeToString(credential) != b.CredentialDigest {
		return out, ErrHubAccountRejected
	}
	out = e2ee.OwnerNativePairScope{Actor: a.scope, Node: appNodeBindingPublic(*b), NodeControlBindingVersion: b.Version, CredentialCommitment: hex.EncodeToString(credential)}
	out.Node.NodeName = known.NodeName
	out.NodeTupleDigest, err = wire.NativePairNodeTupleDigest(out)
	if err != nil || wire.ValidateNativePairScope(out, hub) != nil {
		return e2ee.OwnerNativePairScope{}, ErrHubAccountRejected
	}
	return out, nil
}

func nativePairSameActor(c wire.NativePairRequestContext, a *hubAppNodeActor) bool {
	return c.AccountID == a.scope.AccountID && c.OwnerID == a.scope.OwnerID && c.DeviceID == a.scope.DeviceID && c.HubID == a.scope.HubID && c.Origin == a.scope.Origin
}

func nativePairFresh(c wire.NativePairRequestContext, at time.Time) bool {
	issued, err := time.Parse(time.RFC3339Nano, c.IssuedAt)
	return err == nil && appNodeStamp(issued) == c.IssuedAt && !issued.After(at.Add(30*time.Second)) && at.Before(issued.Add(time.Minute))
}
