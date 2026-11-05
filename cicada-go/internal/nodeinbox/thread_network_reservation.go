package nodeinbox

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"strings"
)

const (
	ThreadNetworkUnassigned  = "UNASSIGNED"
	ThreadNetworkCurrent     = "CURRENT"
	ThreadNetworkReserved    = "RESERVED"
	ThreadNetworkUnresolved  = "UNRESOLVED"
	ThreadNetworkConflict    = "NETWORK_CONFLICT"
	ThreadNetworkAccepted    = "ACCEPTED"
	ThreadNetworkNoEffect    = "NO_EFFECT"
	threadNetworkMaxRevision = uint64(1<<63 - 1)
)

var (
	ErrThreadNetworkUnresolved       = errors.New("native Thread Network original outcome is unresolved")
	ErrThreadNetworkRevisionConflict = errors.New("native Thread Network revision conflicts")
	ErrThreadNetworkOriginalConflict = errors.New("native Thread Network original request conflicts")
	ErrThreadNetworkEvidenceInvalid  = errors.New("authenticated exact original Thread Network result required")
)

// Source coordinates must come from the existing trusted Host/Node verifier.
// Account remains separate metadata: it never creates another identity key.
// No Endpoint or Binding placeholder is accepted by pre-admission reservation.
type ThreadNetworkReservationInput struct {
	AccountID, Harness, NativeSessionID          string
	HubID, NetworkID, OperationID, RequestDigest string
	ExpectedRevision                             uint64
}

// Revision is the immutable claim revision. Inspection.Revision is the current
// authority revision, which can advance while this original is unresolved.
type ThreadNetworkReservation struct {
	ReservationID string `json:"reservation_id"`
	Revision      uint64 `json:"revision"`
	State         string `json:"state"`
	HubID         string `json:"hub_id"`
	NetworkID     string `json:"network_id"`
	OperationID   string `json:"operation_id"`
	RequestDigest string `json:"request_digest"`
}

type ThreadNetworkInspection struct {
	State             string                    `json:"state"`
	Revision          uint64                    `json:"revision"`
	HubID             string                    `json:"hub_id,omitempty"`
	NetworkID         string                    `json:"network_id,omitempty"`
	KnownNetworkCount uint64                    `json:"known_network_count"`
	Reservation       *ThreadNetworkReservation `json:"reservation,omitempty"`
}

// The caller must authenticate/correlate the original remote result before
// constructing this evidence. This registry does not replace the wire verifier.
// A timeout, unsigned HTTP error, missing receipt or mere absence is NOT NoEffect.
type ThreadNetworkSettlement struct {
	Authenticated  bool
	ResponseDigest string
	Accepted       *NativeContextScopeInput
	NoEffect       bool
}

func initializeThreadNetworkSchema(db *sql.DB) error {
	_, err := db.Exec(`CREATE TABLE IF NOT EXISTS node_thread_network_authority_v1(
 identity_digest TEXT PRIMARY KEY, account_digest TEXT NOT NULL,
 hub_id TEXT NOT NULL,network_id TEXT NOT NULL,revision INTEGER NOT NULL CHECK(revision>=0),
 state TEXT NOT NULL,assigned INTEGER NOT NULL CHECK(assigned IN(0,1)),pending_reservation_id TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS node_thread_network_reservations_v1(
 reservation_id TEXT PRIMARY KEY,identity_digest TEXT NOT NULL,account_digest TEXT NOT NULL,
 hub_id TEXT NOT NULL,network_id TEXT NOT NULL,operation_id TEXT NOT NULL,request_digest TEXT NOT NULL,
 expected_revision INTEGER NOT NULL,claim_revision INTEGER NOT NULL,state TEXT NOT NULL,
 response_digest TEXT NOT NULL DEFAULT '',accepted_result_digest TEXT NOT NULL DEFAULT '',
 UNIQUE(identity_digest,operation_id)
);
CREATE INDEX IF NOT EXISTS node_thread_network_reservations_identity_v1 ON node_thread_network_reservations_v1(identity_digest);`)
	return err
}

type threadNetworkAuthority struct {
	exists                                          bool
	identity, account, hub, network, state, pending string
	revision                                        uint64
	assigned                                        bool
}
type threadNetworkOriginal struct {
	reservation                           ThreadNetworkReservation
	identity, account, response, accepted string
	expected                              uint64
}

func threadNetworkText(v string) bool {
	return v != "" && len(v) <= 256 && strings.TrimSpace(v) == v && !strings.ContainsAny(v, "\x00\r\n")
}
func threadNetworkDigest(v string) bool {
	b, e := hex.DecodeString(v)
	return e == nil && len(b) == 32 && hex.EncodeToString(b) == v
}
func threadNetworkSource(account, harness, native string) (string, string, string, string, string, error) {
	account, harness, native = strings.TrimSpace(account), strings.ToLower(strings.TrimSpace(harness)), strings.TrimSpace(native)
	if !threadNetworkText(account) || !threadNetworkText(harness) || !threadNetworkText(native) {
		return "", "", "", "", "", ErrNativeContextScopeInvalid
	}
	return account, harness, native, nativeContextDigest("identity", harness, native), nativeContextDigest("account", account), nil
}
func readThreadNetworkAuthority(ctx context.Context, tx *sql.Tx, identity string) (threadNetworkAuthority, error) {
	a := threadNetworkAuthority{identity: identity}
	var assigned int
	err := tx.QueryRowContext(ctx, `SELECT account_digest,hub_id,network_id,revision,state,assigned,pending_reservation_id FROM node_thread_network_authority_v1 WHERE identity_digest=?`, identity).Scan(&a.account, &a.hub, &a.network, &a.revision, &a.state, &assigned, &a.pending)
	if errors.Is(err, sql.ErrNoRows) {
		return a, nil
	}
	if err != nil {
		return a, err
	}
	a.exists = true
	a.assigned = assigned == 1
	return a, nil
}
func readThreadNetworkOriginal(ctx context.Context, tx *sql.Tx, clause string, args ...any) (*threadNetworkOriginal, error) {
	q := new(threadNetworkOriginal)
	err := tx.QueryRowContext(ctx, `SELECT reservation_id,identity_digest,account_digest,hub_id,network_id,operation_id,request_digest,expected_revision,claim_revision,state,response_digest,accepted_result_digest FROM node_thread_network_reservations_v1 WHERE `+clause, args...).Scan(&q.reservation.ReservationID, &q.identity, &q.account, &q.reservation.HubID, &q.reservation.NetworkID, &q.reservation.OperationID, &q.reservation.RequestDigest, &q.expected, &q.reservation.Revision, &q.reservation.State, &q.response, &q.accepted)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	return q, err
}

// Inspect is a transactionally consistent read; it never guesses one scope from
// conflicting legacy history and never deletes or rewrites historical rows.
func inspectThreadNetworkTx(ctx context.Context, tx *sql.Tx, identity, account string) (*ThreadNetworkInspection, threadNetworkAuthority, error) {
	a, err := readThreadNetworkAuthority(ctx, tx, identity)
	if err != nil {
		return nil, a, err
	}
	v := &ThreadNetworkInspection{State: ThreadNetworkUnassigned, Revision: a.revision}
	conflict := a.exists && a.account != account
	scopes := make(map[string]struct{})
	var hub, network string
	rows, err := tx.QueryContext(ctx, `SELECT account_digest,hub_id,network_id FROM node_native_context_history_v1 WHERE identity_digest=?`, identity)
	if err != nil {
		return nil, a, err
	}
	for rows.Next() {
		var ac, h, n string
		if err = rows.Scan(&ac, &h, &n); err != nil {
			break
		}
		if ac != account || !threadNetworkText(h) || !threadNetworkText(n) {
			conflict = true
		}
		if h != "" && n != "" {
			scopes[h+"\x00"+n] = struct{}{}
			hub, network = h, n
		}
	}
	re := rows.Err()
	rows.Close()
	if err != nil {
		return nil, a, err
	}
	if re != nil {
		return nil, a, re
	}
	v.KnownNetworkCount = uint64(len(scopes))
	if len(scopes) > 1 {
		conflict = true
	}
	if a.exists {
		pendingState := a.state == ThreadNetworkReserved || a.state == ThreadNetworkUnresolved
		if pendingState != (a.pending != "") || a.state == ThreadNetworkCurrent && !a.assigned || a.state == ThreadNetworkUnassigned && (a.assigned || a.hub != "" || a.network != "") || a.assigned && len(scopes) == 0 {
			conflict = true
		}
		if a.revision > threadNetworkMaxRevision || (a.state != ThreadNetworkUnassigned && a.state != ThreadNetworkCurrent && a.state != ThreadNetworkReserved && a.state != ThreadNetworkUnresolved) {
			conflict = true
		}
		if a.state != ThreadNetworkUnassigned && (!threadNetworkText(a.hub) || !threadNetworkText(a.network)) {
			conflict = true
		}
		if len(scopes) == 1 && (a.hub != hub || a.network != network) {
			conflict = true
		}
		v.State, v.HubID, v.NetworkID = a.state, a.hub, a.network
		if a.pending != "" {
			original, e := readThreadNetworkOriginal(ctx, tx, "reservation_id=?", a.pending)
			if e != nil {
				return nil, a, e
			}
			if original == nil || original.identity != identity || original.account != account || original.reservation.HubID != a.hub || original.reservation.NetworkID != a.network || (original.reservation.State != ThreadNetworkReserved && original.reservation.State != ThreadNetworkUnresolved) {
				conflict = true
			} else {
				copy := original.reservation
				v.Reservation = &copy
			}
		}
	} else if len(scopes) == 1 {
		// An implicit first generation for existing history is persisted only
		// by a later writer. Merely inspecting the old DB remains read-only.
		a.account, a.hub, a.network, a.state, a.revision, a.assigned = account, hub, network, ThreadNetworkCurrent, 1, true
		v.State, v.HubID, v.NetworkID, v.Revision = ThreadNetworkCurrent, hub, network, 1
	}
	if conflict {
		v.State = ThreadNetworkConflict
		v.HubID, v.NetworkID = "", ""
		v.Reservation = nil
		if v.Revision == 0 {
			v.Revision = 1
		}
	}
	return v, a, nil
}

func (r *NativeContextRegistry) threadNetworkTransaction(ctx context.Context, action func(*sql.Tx) error) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.closed || r.db == nil {
		return ErrNativeContextRegistryClosed
	}
	// The existing DSN uses _txlock=immediate: reserve the SQLite writer
	// before checking either history or reservations, across all handles.
	tx, err := r.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if err = action(tx); err != nil {
		return err
	}
	return tx.Commit()
}

func (r *NativeContextRegistry) InspectThreadNetwork(ctx context.Context, account, harness, native string) (*ThreadNetworkInspection, error) {
	_, _, _, identity, ac, err := threadNetworkSource(account, harness, native)
	if err != nil {
		return nil, err
	}
	var out *ThreadNetworkInspection
	err = r.threadNetworkTransaction(ctx, func(tx *sql.Tx) error {
		var e error
		out, _, e = inspectThreadNetworkTx(ctx, tx, identity, ac)
		return e
	})
	return out, err
}

func (r *NativeContextRegistry) ReserveThreadNetwork(ctx context.Context, in ThreadNetworkReservationInput) (*ThreadNetworkReservation, error) {
	_, _, _, identity, ac, err := threadNetworkSource(in.AccountID, in.Harness, in.NativeSessionID)
	if err != nil {
		return nil, err
	}
	if !threadNetworkText(in.HubID) || !threadNetworkText(in.NetworkID) || !threadNetworkText(in.OperationID) || !threadNetworkDigest(in.RequestDigest) || in.ExpectedRevision >= threadNetworkMaxRevision {
		return nil, ErrNativeContextScopeInvalid
	}
	var out *ThreadNetworkReservation
	err = r.threadNetworkTransaction(ctx, func(tx *sql.Tx) error {
		v, a, e := inspectThreadNetworkTx(ctx, tx, identity, ac)
		if e != nil {
			return e
		}
		if v.State == ThreadNetworkConflict {
			return ErrNativeContextScopeConflict
		}
		old, e := readThreadNetworkOriginal(ctx, tx, "identity_digest=? AND operation_id=?", identity, in.OperationID)
		if e != nil {
			return e
		}
		if old != nil {
			if old.account != ac || old.reservation.HubID != in.HubID || old.reservation.NetworkID != in.NetworkID || old.reservation.RequestDigest != in.RequestDigest || old.expected != in.ExpectedRevision {
				return ErrThreadNetworkOriginalConflict
			}
			copy := old.reservation
			out = &copy
			return nil
		}
		if v.State != ThreadNetworkUnassigned && (v.HubID != in.HubID || v.NetworkID != in.NetworkID) {
			return ErrNativeContextScopeConflict
		}
		if a.pending != "" {
			return ErrThreadNetworkUnresolved
		}
		if v.Revision != in.ExpectedRevision {
			return ErrThreadNetworkRevisionConflict
		}
		for _, q := range []struct {
			sql  string
			args []any
			cap  int
		}{
			{`SELECT count(*) FROM node_thread_network_reservations_v1 WHERE identity_digest=?`, []any{identity}, r.perIdentityCap},
			{`SELECT count(*) FROM node_thread_network_reservations_v1`, nil, r.globalHistoryCap},
			{`SELECT count(*) FROM node_native_context_history_v1 WHERE identity_digest=?`, []any{identity}, r.perIdentityCap},
			{`SELECT count(*) FROM node_native_context_history_v1`, nil, r.globalHistoryCap},
		} {
			var count int
			if e = tx.QueryRowContext(ctx, q.sql, q.args...).Scan(&count); e != nil {
				return e
			}
			if count >= q.cap {
				return ErrNativeContextHistoryAtLimit
			}
		}
		id, e := randomNativeContextRecordID()
		if e != nil {
			return e
		}
		claim := ThreadNetworkReservation{id, v.Revision + 1, ThreadNetworkReserved, in.HubID, in.NetworkID, in.OperationID, in.RequestDigest}
		if _, e = tx.ExecContext(ctx, `INSERT INTO node_thread_network_reservations_v1 VALUES(?,?,?,?,?,?,?,?,?,?,'','')`, id, identity, ac, in.HubID, in.NetworkID, in.OperationID, in.RequestDigest, in.ExpectedRevision, claim.Revision, claim.State); e != nil {
			return e
		}
		_, e = tx.ExecContext(ctx, `INSERT INTO node_thread_network_authority_v1 VALUES(?,?,?,?,?,?,?,?) ON CONFLICT(identity_digest) DO UPDATE SET hub_id=excluded.hub_id,network_id=excluded.network_id,revision=excluded.revision,state=excluded.state,pending_reservation_id=excluded.pending_reservation_id`, identity, ac, in.HubID, in.NetworkID, claim.Revision, ThreadNetworkReserved, a.assigned, id)
		if e == nil {
			out = &claim
		}
		return e
	})
	return out, err
}

func matchThreadNetworkReservation(original *threadNetworkOriginal, r ThreadNetworkReservation) bool {
	return original != nil && original.reservation.ReservationID == r.ReservationID && original.reservation.Revision == r.Revision && original.reservation.HubID == r.HubID && original.reservation.NetworkID == r.NetworkID && original.reservation.OperationID == r.OperationID && original.reservation.RequestDigest == r.RequestDigest
}

func (r *NativeContextRegistry) MarkThreadNetworkUnresolved(ctx context.Context, claim ThreadNetworkReservation) (*ThreadNetworkInspection, error) {
	var out *ThreadNetworkInspection
	err := r.threadNetworkTransaction(ctx, func(tx *sql.Tx) error {
		o, e := readThreadNetworkOriginal(ctx, tx, "reservation_id=?", claim.ReservationID)
		if e != nil {
			return e
		}
		if !matchThreadNetworkReservation(o, claim) {
			return ErrThreadNetworkOriginalConflict
		}
		v, a, e := inspectThreadNetworkTx(ctx, tx, o.identity, o.account)
		if e != nil {
			return e
		}
		if v.State == ThreadNetworkConflict {
			return ErrNativeContextScopeConflict
		}
		if o.reservation.State == ThreadNetworkAccepted || o.reservation.State == ThreadNetworkNoEffect {
			out = v
			return nil
		}
		if a.pending != claim.ReservationID {
			return ErrThreadNetworkOriginalConflict
		}
		if o.reservation.State == ThreadNetworkReserved {
			if a.revision >= threadNetworkMaxRevision {
				return ErrNativeContextHistoryAtLimit
			}
			if _, e = tx.ExecContext(ctx, `UPDATE node_thread_network_reservations_v1 SET state=? WHERE reservation_id=?`, ThreadNetworkUnresolved, claim.ReservationID); e != nil {
				return e
			}
			if _, e = tx.ExecContext(ctx, `UPDATE node_thread_network_authority_v1 SET state=?,revision=revision+1 WHERE identity_digest=?`, ThreadNetworkUnresolved, o.identity); e != nil {
				return e
			}
		}
		out, _, e = inspectThreadNetworkTx(ctx, tx, o.identity, o.account)
		return e
	})
	return out, err
}

func (r *NativeContextRegistry) SettleThreadNetwork(ctx context.Context, claim ThreadNetworkReservation, evidence ThreadNetworkSettlement) (*ThreadNetworkInspection, error) {
	if !evidence.Authenticated || !threadNetworkDigest(evidence.ResponseDigest) || (evidence.Accepted != nil) == evidence.NoEffect {
		return nil, ErrThreadNetworkEvidenceInvalid
	}
	var out *ThreadNetworkInspection
	err := r.threadNetworkTransaction(ctx, func(tx *sql.Tx) error {
		o, e := readThreadNetworkOriginal(ctx, tx, "reservation_id=?", claim.ReservationID)
		if e != nil {
			return e
		}
		if !matchThreadNetworkReservation(o, claim) {
			return ErrThreadNetworkOriginalConflict
		}
		v, a, e := inspectThreadNetworkTx(ctx, tx, o.identity, o.account)
		if e != nil {
			return e
		}
		if v.State == ThreadNetworkConflict {
			return ErrNativeContextScopeConflict
		}
		state, accepted := ThreadNetworkNoEffect, ""
		var input NativeContextScopeInput
		if evidence.Accepted != nil {
			var identity, account string
			input, identity, account, e = normalizeNativeContextScopeInput(*evidence.Accepted)
			if e != nil || identity != o.identity || account != o.account || input.HubID != claim.HubID || input.NetworkID != claim.NetworkID {
				return ErrThreadNetworkEvidenceInvalid
			}
			raw, e := json.Marshal(input)
			if e != nil {
				return e
			}
			digest := sha256.Sum256(raw)
			clear(raw)
			accepted = hex.EncodeToString(digest[:])
			state = ThreadNetworkAccepted
		}
		if o.reservation.State == ThreadNetworkAccepted || o.reservation.State == ThreadNetworkNoEffect {
			if o.reservation.State != state || o.response != evidence.ResponseDigest || o.accepted != accepted {
				return ErrThreadNetworkOriginalConflict
			}
			out = v
			return nil
		}
		if a.pending != claim.ReservationID {
			return ErrThreadNetworkOriginalConflict
		}
		if a.revision >= threadNetworkMaxRevision {
			return ErrNativeContextHistoryAtLimit
		}
		if state == ThreadNetworkAccepted {
			if _, e = r.recordNativeContextTx(ctx, tx, input, o.identity, o.account, input.GroupID == "", claim.ReservationID); e != nil {
				return e
			}
			a.assigned = true
		}
		if _, e = tx.ExecContext(ctx, `UPDATE node_thread_network_reservations_v1 SET state=?,response_digest=?,accepted_result_digest=? WHERE reservation_id=?`, state, evidence.ResponseDigest, accepted, claim.ReservationID); e != nil {
			return e
		}
		nextState, hub, network := ThreadNetworkCurrent, claim.HubID, claim.NetworkID
		if !a.assigned {
			nextState, hub, network = ThreadNetworkUnassigned, "", ""
		}
		if _, e = tx.ExecContext(ctx, `UPDATE node_thread_network_authority_v1 SET state=?,hub_id=?,network_id=?,assigned=?,pending_reservation_id='',revision=revision+1 WHERE identity_digest=?`, nextState, hub, network, a.assigned, o.identity); e != nil {
			return e
		}
		out, _, e = inspectThreadNetworkTx(ctx, tx, o.identity, o.account)
		return e
	})
	return out, err
}

func guardThreadNetworkRecordTx(ctx context.Context, tx *sql.Tx, identity, account, hub, network, settling string) error {
	v, a, err := inspectThreadNetworkTx(ctx, tx, identity, account)
	if err != nil {
		return err
	}
	if v.State == ThreadNetworkConflict {
		return ErrNativeContextScopeConflict
	}
	if v.State != ThreadNetworkUnassigned && (v.HubID != hub || v.NetworkID != network) {
		return ErrNativeContextScopeConflict
	}
	if a.pending != "" && a.pending != settling {
		return ErrThreadNetworkUnresolved
	}
	return nil
}
func assignThreadNetworkRecordTx(ctx context.Context, tx *sql.Tx, identity, account, hub, network string) error {
	a, err := readThreadNetworkAuthority(ctx, tx, identity)
	if err != nil {
		return err
	}
	if a.exists && a.assigned && a.state == ThreadNetworkCurrent {
		return nil
	}
	if a.revision >= threadNetworkMaxRevision {
		return ErrNativeContextHistoryAtLimit
	}
	_, err = tx.ExecContext(ctx, `INSERT INTO node_thread_network_authority_v1 VALUES(?,?,?,?,?,? ,1,'') ON CONFLICT(identity_digest) DO UPDATE SET hub_id=excluded.hub_id,network_id=excluded.network_id,revision=excluded.revision,state=excluded.state,assigned=1,pending_reservation_id=''`, identity, account, hub, network, a.revision+1, ThreadNetworkCurrent)
	return err
}
