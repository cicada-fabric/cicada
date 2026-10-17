package store

import (
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"math"
	"reflect"
	"time"

	"github.com/cicada-ai/cicada/internal/clientwire"
	"github.com/cicada-ai/cicada/internal/e2ee"
	wire "github.com/cicada-ai/cicada/internal/hubaccountwire"
	"github.com/cicada-ai/cicada/internal/nodewire"
)

type HubAppNodeClientSeal func(responseSequence uint64, requestID string, binding *NodeControlKeyBinding, errorCode string) ([]byte, error)
type HubAppNodeClientInput struct {
	Hub                   wire.HubIdentity
	NodeControlPublic     e2ee.PublicIdentity
	Device                e2ee.PublicIdentity
	Packet                []byte
	Route                 clientwire.Route
	Code, CandidateDigest string
	CandidateVersion      uint64
	At                    time.Time
	Seal                  HubAppNodeClientSeal
}

// ProcessHubAppNodeClient is the sole N3 business admission path. It does not
// call the legacy admission/dispatch pair, which cannot atomically commit the
// Node effect with its budget, counters and exact sealed response.
func (s *Store) ProcessHubAppNodeClient(in HubAppNodeClientInput) ([]byte, error) {
	if s.requireOwnerSetupStartupAllowed() != nil {
		return nil, ErrHubAccountRejected
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	tx, err := s.db.Begin()
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()
	a, err := appNodeActor(tx, in.Hub, in.Route.DeviceID, in.Device, nil, in.At)
	if err != nil {
		return nil, err
	}
	if err = appNodeRefresh(tx, a, in.At); err != nil {
		return nil, err
	}
	packet, _, err := appNodeClient(tx, a, in, false)
	if err != nil {
		return nil, err
	}
	if err = tx.Commit(); err != nil {
		return nil, err
	}
	return packet, nil
}

func appNodeClient(tx *sql.Tx, a *hubAppNodeActor, in HubAppNodeClientInput, fence bool) ([]byte, string, error) {
	r := in.Route
	grantID, _, err := wire.ParseAppNodeBusinessOperationID(r.OperationID)
	var original clientwire.Packet
	if err != nil || in.Seal == nil || in.At.IsZero() || len(in.Packet) == 0 || len(in.Packet) > wire.MaxAppNodeOriginalBytes || json.Unmarshal(in.Packet, &original) != nil || original.Route != r || r.Version != 1 || r.SessionEpoch == 0 || r.SessionEpoch > math.MaxInt64 || r.Direction != clientwire.DirectionRequest || r.Operation != "nodes.confirm" || r.OwnerID != a.scope.OwnerID || r.DeviceID != a.scope.DeviceID || r.HubID != a.scope.HubID || r.SenderKeyID != a.scope.DevicePublic.ID || r.ReceiverKeyID != in.Hub.Public.ID || r.SenderKeyVersion != 1 || r.ReceiverKeyVersion != 1 || r.Sequence == 0 || r.Sequence > math.MaxInt64 {
		return nil, "", ErrHubAccountRejected
	}
	digest := wire.AppNodePacketDigest(in.Packet)
	if packet, state, err := appNodeCached(tx, r.OwnerID, r.DeviceID, r.OperationID, r.Operation, digest, in.At); err != nil || len(packet) > 0 {
		return packet, state, err
	}
	g, err := appNodeGrant(tx, r.OwnerID, r.DeviceID, grantID)
	if err != nil {
		return nil, "", err
	}
	if g == nil {
		return nil, "", ErrHubAccountRejected
	}
	// A record without the atomic N3 receipt/provenance cannot be inferred from
	// a Node with the same ID. Legacy uncertain/processing rows stay unresolved.
	var oldID string
	err = tx.QueryRow(`SELECT id FROM client_device_requests_v2 WHERE owner_id=? AND device_id=? AND operation_id=?`, r.OwnerID, r.DeviceID, r.OperationID).Scan(&oldID)
	if err == nil {
		return nil, "", ErrClientRequestStateConflict
	}
	if !errors.Is(err, sql.ErrNoRows) {
		return nil, "", err
	}
	if r.SessionEpoch != a.counters.SessionEpoch || r.Sequence != a.counters.LastRequestSequence+1 || a.counters.NextResponseSequence == 0 || a.counters.NextResponseSequence >= math.MaxInt64 {
		return nil, "", ErrClientRequestSequence
	}
	h, err := appNodeHead(tx, r.OwnerID, r.DeviceID)
	if err != nil {
		return nil, "", err
	}
	errorCode := ""
	if fence {
		errorCode = "INVALID_REQUEST"
	} else if !a.source || !appNodeSameSecurity(a.scope, g.claims.Scope) || h.latest != grantID || h.version != g.claims.Scope.HeadVersion || r.SessionEpoch != g.claims.Scope.ClientSessionEpoch {
		errorCode = "AUTHORITY_REVOKED"
	} else if g.state == wire.AppNodeExpired || !appNodeBefore(in.At, g.claims.LeaseExpiresAt) {
		errorCode = "AUTHORITY_EXPIRED"
	} else if g.state == wire.AppNodeSessionEnded {
		errorCode = "SESSION_REQUIRED"
	} else if g.state != wire.AppNodeActive {
		errorCode = "AUTHORITY_REVOKED"
	} else if session, e := appNodeSession(tx, g.claims.Scope, g.claims.Scope.AccountSessionID, in.At); e != nil || session.ExpiresAt != g.claims.Scope.AccountSessionExpiresAt {
		errorCode = "SESSION_REQUIRED"
	} else if g.claims.Profile != wire.AppNodeProfileInitial || g.claims.Candidate == nil || g.remaining != 1 || g.provenance != "" || h.provenance != "" {
		errorCode = "CONFIRMATION_USED"
	}
	var binding *NodeControlKeyBinding
	if errorCode == "" {
		code, e := wire.AppNodeCodeDigest(r.HubID, in.Code)
		if e != nil || code != g.claims.Candidate.CodeDigest || in.CandidateDigest != g.claims.Candidate.CandidateDigest || in.CandidateVersion != g.claims.Candidate.Version {
			errorCode = "CANDIDATE_CHANGED"
		} else {
			candidate, e := appNodeCandidate(tx, code, in.Hub, in.NodeControlPublic, in.At)
			if e != nil || !reflect.DeepEqual(candidate, g.claims.Candidate) {
				errorCode = "CANDIDATE_CHANGED"
			} else {
				if _, err = tx.Exec(`SAVEPOINT n3_confirm_effect`); err != nil {
					return nil, "", err
				}
				binding, err = confirmNodeControlKeyRequestTx(tx, r.OwnerID, r.DeviceID, code, int64(in.CandidateVersion), in.CandidateDigest, in.NodeControlPublic.ID, nodewire.IdentityFingerprint(in.NodeControlPublic), in.At)
				if err != nil {
					if _, e = tx.Exec(`ROLLBACK TO n3_confirm_effect`); e != nil {
						return nil, "", e
					}
					if !errors.Is(err, ErrNodeControlPairingConflict) && !errors.Is(err, ErrNodeControlPairingChanged) && !errors.Is(err, ErrNodeControlPairingNotFound) && !errors.Is(err, ErrNodeControlMigrationBlocked) && !errors.Is(err, ErrNodeDeviceBindingUnauthorized) && !errors.Is(err, ErrNodeMachineOwnershipConflict) {
						return nil, "", err
					}
					binding = nil
					errorCode = "CANDIDATE_CHANGED"
				}
				if _, err = tx.Exec(`RELEASE n3_confirm_effect`); err != nil {
					return nil, "", err
				}
			}
		}
	}
	requestID := NewID("clientreq")
	packet, err := in.Seal(a.counters.NextResponseSequence, requestID, binding, errorCode)
	if err != nil {
		return nil, "", err
	}
	if len(packet) == 0 || len(packet) > wire.MaxAppNodeReceiptBytes {
		return nil, "", ErrHubAccountRejected
	}
	stamp := appNodeStamp(in.At)
	changed, err := tx.Exec(`UPDATE client_devices_v2 SET last_request_sequence=?,next_response_sequence=next_response_sequence+1,updated_at=? WHERE owner_id=? AND device_id=? AND session_epoch=? AND last_request_sequence=? AND next_response_sequence=?`, r.Sequence, stamp, r.OwnerID, r.DeviceID, r.SessionEpoch, a.counters.LastRequestSequence, a.counters.NextResponseSequence)
	if err != nil {
		return nil, "", err
	}
	if n, e := changed.RowsAffected(); e != nil || n != 1 {
		return nil, "", ErrClientRequestSequence
	}
	hash := sha256.Sum256(in.Packet)
	oldDigest := hex.EncodeToString(hash[:])
	_, err = tx.Exec(`INSERT INTO client_device_requests_v2(id,owner_id,device_id,session_epoch,sequence,operation_id,route_operation,ciphertext_digest,status,response_packet,created_at,updated_at) VALUES(?,?,?,?,?,?,?,?,'COMPLETED',?,?,?)`, requestID, r.OwnerID, r.DeviceID, r.SessionEpoch, r.Sequence, r.OperationID, r.Operation, oldDigest, packet, stamp, stamp)
	if err != nil {
		return nil, "", err
	}
	if _, err = tx.Exec(`INSERT INTO client_device_request_recovery_v2(request_id,reserved_response_sequence,recovery_packet,created_at,updated_at) VALUES(?,?,?,?,?)`, requestID, a.counters.NextResponseSequence, packet, stamp, stamp); err != nil {
		return nil, "", err
	}
	state := wire.AppNodeRejectedFenced
	if binding != nil && errorCode == "" {
		state = wire.AppNodeCompleted
		if wire.ValidateAppNodeConfirmationBinding(g.claims, appNodeBindingPublic(*binding)) != nil {
			return nil, "", ErrNodeControlPairingChanged
		}
		provenance, err := wire.NewRequestID()
		if err != nil {
			return nil, "", err
		}
		raw, err := json.Marshal(binding)
		if err != nil {
			return nil, "", err
		}
		if _, err = tx.Exec(`INSERT INTO hub_app_node_provenance_v1(provenance_id,grant_id,owner_id,device_id,client_request_id,operation_id,request_digest,head_version,binding_json,created_at) VALUES(?,?,?,?,?,?,?,?,?,?)`, provenance, grantID, r.OwnerID, r.DeviceID, requestID, r.OperationID, oldDigest, h.version, string(raw), stamp); err != nil {
			return nil, "", err
		}
		if _, err = tx.Exec(`UPDATE hub_app_node_grants_v1 SET remaining=0,provenance_id=? WHERE grant_id=? AND state='ACTIVE' AND remaining=1`, provenance, grantID); err != nil {
			return nil, "", err
		}
		if _, err = tx.Exec(`UPDATE hub_app_node_heads_v1 SET provenance_id=? WHERE owner_id=? AND device_id=?`, provenance, r.OwnerID, r.DeviceID); err != nil {
			return nil, "", err
		}
	}
	_, err = tx.Exec(`INSERT INTO hub_app_node_operations_v1(owner_id,device_id,operation_id,operation,kind,request_digest,state,response_packet,created_at) VALUES(?,?,?,?,'CLIENT_CONTROL',?,?,?,?)`, r.OwnerID, r.DeviceID, r.OperationID, r.Operation, digest, state, packet, stamp)
	if err != nil {
		return nil, "", err
	}
	return packet, state, nil
}
