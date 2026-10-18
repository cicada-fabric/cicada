package store

import (
	"database/sql"
	"encoding/hex"
	"errors"
	"reflect"
	"time"

	"github.com/cicada-ai/cicada/internal/e2ee"
	wire "github.com/cicada-ai/cicada/internal/hubaccountwire"
)

type nativePairReceipt struct {
	packet      []byte
	state, pair string
}

func nativePairCached(tx *sql.Tx, c wire.NativePairRequestContext, op, digest string, at time.Time) (nativePairReceipt, error) {
	var r nativePairReceipt
	var savedOp, savedDigest string
	err := tx.QueryRow(`SELECT operation,request_digest,state,pair_id,response_packet FROM hub_native_pair_operations_v1 WHERE owner_id=? AND device_id=? AND operation_id=?`, c.OwnerID, c.DeviceID, c.RequestID).Scan(&savedOp, &savedDigest, &r.state, &r.pair, &r.packet)
	if err == nil {
		if savedOp != op || savedDigest != digest {
			return nativePairReceipt{}, ErrHubAccountRejected
		}
		return r, nil
	}
	if !errors.Is(err, sql.ErrNoRows) {
		return r, err
	}
	var created string
	err = tx.QueryRow(`SELECT operation,request_digest,state,pair_id,response_packet,created_at FROM hub_native_pair_reads_v1 WHERE owner_id=? AND device_id=? AND operation_id=?`, c.OwnerID, c.DeviceID, c.RequestID).Scan(&savedOp, &savedDigest, &r.state, &r.pair, &r.packet, &created)
	if err == nil {
		if savedOp != op || savedDigest != digest {
			return nativePairReceipt{}, ErrHubAccountRejected
		}
		start, e := time.Parse(time.RFC3339Nano, created)
		if e != nil {
			return nativePairReceipt{}, ErrHubAccountRejected
		}
		if at.Before(start.Add(5 * time.Minute)) {
			return r, nil
		}
		return nativePairReceipt{}, nil
	}
	if errors.Is(err, sql.ErrNoRows) {
		return nativePairReceipt{}, nil
	}
	return r, err
}

func nativePairNonce(tx *sql.Tx, c wire.NativePairRequestContext) (string, error) {
	digest := AccountDigest("native-pair-nonce", c.ClientNonce)
	var count int
	if err := tx.QueryRow(`SELECT count(*) FROM hub_native_pair_operations_v1 WHERE owner_id=? AND device_id=? AND nonce_digest=?`, c.OwnerID, c.DeviceID, digest).Scan(&count); err != nil {
		return "", err
	}
	if count != 0 {
		return "", ErrHubAccountRejected
	}
	return digest, nil
}

func nativePairSaveMutation(tx *sql.Tx, c wire.NativePairRequestContext, op, pair, digest, state, nonce string, packet []byte, at time.Time) error {
	if len(packet) == 0 || len(packet) > wire.MaxNativePairReceiptBytes {
		return ErrHubAccountRejected
	}
	_, err := tx.Exec(`INSERT INTO hub_native_pair_operations_v1(owner_id,device_id,operation_id,operation,pair_id,request_digest,state,nonce_digest,response_packet,created_at) VALUES(?,?,?,?,?,?,?,?,?,?)`, c.OwnerID, c.DeviceID, c.RequestID, op, pair, digest, state, nonce, packet, appNodeStamp(at))
	return err
}

func nativePairSaveRead(tx *sql.Tx, c wire.NativePairRequestContext, op, pair, digest, state string, packet []byte, at time.Time) error {
	if len(packet) == 0 || len(packet) > wire.MaxNativePairReconcilePacketBytes {
		return ErrHubAccountRejected
	}
	rows, err := tx.Query(`SELECT operation_id,created_at FROM hub_native_pair_reads_v1 WHERE owner_id=? AND device_id=? ORDER BY rowid DESC`, c.OwnerID, c.DeviceID)
	if err != nil {
		return err
	}
	var drop []string
	type entry struct {
		id        string
		protected bool
	}
	var live []entry
	protected := 0
	for rows.Next() {
		var id, created string
		if err = rows.Scan(&id, &created); err != nil {
			break
		}
		start, e := time.Parse(time.RFC3339Nano, created)
		if e != nil {
			err = ErrHubAccountRejected
			break
		}
		if !at.Before(start.Add(5 * time.Minute)) {
			drop = append(drop, id)
		} else {
			// A first admitted read may be issued 30 seconds ahead. Keep its
			// exact receipt until the entire 60-second freshness interval is
			// over, so an evicted ID can never acquire a new observation.
			hold := at.Before(start.Add(90 * time.Second))
			live = append(live, entry{id, hold})
			if hold {
				protected++
			}
		}
	}
	re := rows.Err()
	rows.Close()
	if err != nil {
		return err
	}
	if re != nil {
		return re
	}
	if protected >= 128 {
		return ErrHubOwnerDiagnosticsFull
	}
	olderCapacity := 127 - protected
	for _, row := range live {
		if row.id == c.RequestID {
			return ErrHubAccountRejected
		}
		if row.protected {
			continue
		}
		if olderCapacity > 0 {
			olderCapacity--
		} else {
			drop = append(drop, row.id)
		}
	}
	for _, id := range drop {
		if _, err = tx.Exec(`DELETE FROM hub_native_pair_reads_v1 WHERE owner_id=? AND device_id=? AND operation_id=?`, c.OwnerID, c.DeviceID, id); err != nil {
			return err
		}
	}
	_, err = tx.Exec(`INSERT INTO hub_native_pair_reads_v1(owner_id,device_id,operation_id,operation,pair_id,request_digest,state,response_packet,created_at) VALUES(?,?,?,?,?,?,?,?,?)`, c.OwnerID, c.DeviceID, c.RequestID, op, pair, digest, state, packet, appNodeStamp(at))
	return err
}

func nativePairReadRate(tx *sql.Tx, c wire.NativePairRequestContext, at time.Time) error {
	var stamp string
	var count int
	err := tx.QueryRow(`SELECT window_start,requests FROM hub_native_pair_rates_v1 WHERE owner_id=? AND device_id=?`, c.OwnerID, c.DeviceID).Scan(&stamp, &count)
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		return err
	}
	start, e := time.Parse(time.RFC3339Nano, stamp)
	if e != nil || !at.Before(start.Add(time.Minute)) {
		stamp = appNodeStamp(at)
		count = 0
	}
	if count >= 128 {
		return ErrHubOwnerDiagnosticsFull
	}
	_, err = tx.Exec(`INSERT INTO hub_native_pair_rates_v1 VALUES(?,?,?,?) ON CONFLICT(owner_id,device_id) DO UPDATE SET window_start=excluded.window_start,requests=excluded.requests`, c.OwnerID, c.DeviceID, stamp, count+1)
	return err
}

// Authenticate/decrypt with the retained registered App key first. The SQLite
// writer is acquired before sampling time, authority or replay state. Effects,
// nonce, permanent rejection fence and sealed exact receipt commit together.
func (s *Store) ProcessHubNativePair(in HubNativePairInput, seal HubNativePairSeal) ([]byte, error) {
	if s.requireOwnerSetupStartupAllowed() != nil || seal == nil {
		return nil, ErrHubAccountRejected
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	tx, err := s.db.Begin()
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()
	guard, err := tx.Exec(`UPDATE hub_native_pair_guard_v1 SET touched_at=touched_at WHERE id=1`)
	if err != nil {
		return nil, err
	}
	if n, e := guard.RowsAffected(); e != nil || n != 1 {
		return nil, ErrHubAccountRejected
	}
	if in.Now != nil {
		in.At = in.Now().UTC()
	}
	c, token, _, _, _, err := nativePairInput(in)
	if err != nil {
		return nil, err
	}
	a, err := appNodeActor(tx, in.Hub, c.DeviceID, in.Device, token, in.At)
	if err != nil || !nativePairSameActor(c, a) {
		return nil, ErrHubAccountRejected
	}
	receipt, err := nativePairProcessTx(tx, a, in, seal, false)
	if err != nil {
		return nil, err
	}
	if err = tx.Commit(); err != nil {
		return nil, err
	}
	return receipt.packet, nil
}

func nativePairFence(tx *sql.Tx, c wire.NativePairRequestContext, op, pair, digest, nonce, code string, seal HubNativePairSeal, at time.Time) (nativePairReceipt, error) {
	var body any
	if op == wire.OperationNativePairBootstrapPrepare {
		// A rejected/unadmitted prepare has no published ID, including failures
		// after local random allocation but before its INSERT/savepoint commits.
		pair = ""
		body = wire.NativePairBootstrapFence{Format: wire.NativePairFormat, Operation: op, RequestID: c.RequestID, RequestPacketDigest: digest, State: "REJECTED_FENCED", NoEffect: true, ErrorCode: code, ObservedAt: appNodeStamp(at)}
	} else {
		body = wire.NativePairRejectionFence{Format: wire.NativePairFormat, Operation: op, RequestID: c.RequestID, RequestPacketDigest: digest, PairID: pair, State: "REJECTED_FENCED", NoEffect: true, ErrorCode: code, ObservedAt: appNodeStamp(at)}
	}
	packet, err := seal(body)
	if err != nil {
		return nativePairReceipt{}, err
	}
	if err = nativePairSaveMutation(tx, c, op, pair, digest, "REJECTED_FENCED", nonce, packet, at); err != nil {
		return nativePairReceipt{}, err
	}
	return nativePairReceipt{packet: packet, state: "REJECTED_FENCED", pair: pair}, nil
}

func nativePairProcessTx(tx *sql.Tx, a *hubAppNodeActor, in HubNativePairInput, seal HubNativePairSeal, fence bool) (nativePairReceipt, error) {
	c, _, raw, op, pair, err := nativePairInput(in)
	if err != nil || !nativePairSameActor(c, a) {
		return nativePairReceipt{}, ErrHubAccountRejected
	}
	digest := wire.NativePairPacketDigest(in.Packet)
	old, err := nativePairCached(tx, c, op, digest, in.At)
	if err != nil || len(old.packet) > 0 {
		return old, err
	}
	if op == wire.OperationNativePairStatus {
		return nativePairStatusTx(tx, a, in, seal, fence)
	}
	if op == wire.OperationNativePairReconcile {
		return nativePairReconcileTx(tx, a, in, seal)
	}
	claims, err := e2ee.VerifyOwnerNativePair(a.scope.OwnerPublic, raw, wire.NativePairOwnerPurpose(op), time.Time{})
	if err != nil {
		return nativePairReceipt{}, ErrHubAccountRejected
	}
	nonce, ne := nativePairNonce(tx, c)
	if ne != nil {
		nonce = ""
	}
	if fence {
		return nativePairFence(tx, c, op, pair, digest, nonce, "REJECTED_UNADMITTED", seal, in.At)
	}
	code := ""
	if ne != nil {
		code = "REPLAY_CONFLICT"
	} else if !nativePairFresh(c, in.At) {
		code = "PROOF_EXPIRED"
	} else if e2ee.ValidateOwnerNativePairClaims(claims, in.At) != nil {
		code = "PROOF_EXPIRED"
	}
	current, se := nativePairCurrentScope(tx, a, claims.Scope.Node, in.Hub, in.NodeControlPublic)
	if code == "" && se != nil {
		code = "AUTHORITY_UNAVAILABLE"
	}
	if code == "" {
		wanted := current
		if op == wire.OperationNativePairBootstrapPrepare {
			wanted.NodeControlBindingVersion = 0
			wanted.CredentialCommitment = ""
			wanted.NodeTupleDigest = ""
		}
		if !reflect.DeepEqual(wanted, claims.Scope) {
			code = "SCOPE_MISMATCH"
		}
	}
	if code != "" {
		return nativePairFence(tx, c, op, pair, digest, nonce, code, seal, in.At)
	}
	if _, err = tx.Exec(`SAVEPOINT native_pair_effect`); err != nil {
		return nativePairReceipt{}, err
	}
	var body any
	switch op {
	case wire.OperationNativePairBootstrapPrepare:
		body, pair, err = nativePairPrepareTx(tx, a, current, claims, c, digest, in.At, in.Hub)
	case wire.OperationNativePairBootstrapComplete:
		body, err = nativePairCompleteTx(tx, a, claims, raw, c, digest, in.At)
	case wire.OperationNativePairConsentPrepare:
		body, err = nativePairConsentPrepareTx(tx, a, claims, c, digest, in.At)
	case wire.OperationNativePairConsentComplete:
		q, ok := in.Body.(wire.NativePairConsentComplete)
		if !ok {
			err = ErrHubAccountRejected
		} else {
			body, err = nativePairConsentCompleteTx(tx, a, claims, raw, q.GroupKeyProof, c, digest, in.At)
		}
	case wire.OperationNativePairSlotReject:
		body, err = nativePairSlotRejectTx(tx, a, claims, c, digest, in.At)
	case wire.OperationNativePairRevoke:
		body, err = nativePairRevokeTx(tx, a, claims, c, digest, in.At)
	default:
		err = ErrHubAccountRejected
	}
	if err != nil {
		if _, re := tx.Exec(`ROLLBACK TO native_pair_effect`); re != nil {
			return nativePairReceipt{}, re
		}
		if _, re := tx.Exec(`RELEASE native_pair_effect`); re != nil {
			return nativePairReceipt{}, re
		}
		return nativePairFence(tx, c, op, pair, digest, nonce, "TARGET_UNAVAILABLE", seal, in.At)
	}
	if _, err = tx.Exec(`RELEASE native_pair_effect`); err != nil {
		return nativePairReceipt{}, err
	}
	packet, err := seal(body)
	if err != nil {
		return nativePairReceipt{}, err
	}
	if err = nativePairSaveMutation(tx, c, op, pair, digest, "COMPLETED", nonce, packet, in.At); err != nil {
		return nativePairReceipt{}, err
	}
	return nativePairReceipt{packet: packet, state: "COMPLETED", pair: pair}, nil
}

func nativePairExpireTx(tx *sql.Tx, p *hubNativePair, at time.Time) error {
	if p.state == wire.NativePairRevoked || p.state == wire.NativePairExpired {
		return nil
	}
	reason := ""
	if !appNodeBefore(at, p.peerExpires) {
		reason = "PEER_EXPIRED"
	} else if p.state == wire.NativePairPrepared && !appNodeBefore(at, p.proofExpires) {
		reason = "BOOTSTRAP_EXPIRED"
	} else if p.state == wire.NativePairWaitingJoin && !appNodeBefore(at, p.joinUntil) {
		reason = "JOIN_EXPIRED"
	}
	if reason == "" {
		return nil
	}
	if _, err := tx.Exec(`UPDATE hub_native_pairs_v1 SET state='EXPIRED',control_revision=control_revision+1,terminal_reason=? WHERE pair_id=? AND control_revision=?`, reason, p.id, p.revision); err != nil {
		return err
	}
	p.state = wire.NativePairExpired
	p.revision++
	p.reason = reason
	return nil
}

func nativePairOwned(tx *sql.Tx, a *hubAppNodeActor, id string, at time.Time) (*hubNativePair, error) {
	p, err := readNativePair(tx, id)
	if err != nil || p == nil {
		return nil, ErrHubAccountRejected
	}
	if p.owner != a.scope.OwnerID || p.device != a.scope.DeviceID || p.account != a.scope.AccountID || p.hub != a.scope.HubID {
		return nil, ErrHubAccountRejected
	}
	if err = nativePairExpireTx(tx, p, at); err != nil {
		return nil, err
	}
	return p, nil
}

func nativePairProofNonce(n []byte) string { return hex.EncodeToString(n) }
