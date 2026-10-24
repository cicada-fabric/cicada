package store

import (
	"database/sql"
	"errors"
	"time"

	wire "github.com/cicada-ai/cicada/internal/hubaccountwire"
)

var nodePairTrustBudgetObjects = []string{"hub_node_pair_trust_budget_v1", "hub_node_pair_trust_reads_v1", "hub_node_pair_trust_reads_v1_expiry", "hub_node_pair_trust_reads_v1_attempt", "hub_node_pair_trust_rates_v1", "hub_node_pair_trust_rates_v1_expiry", "hub_node_pair_trust_v1_gc", "node_control_pair_trust_gc_v1", "node_control_pair_trust_required_no_delete_v1", "hub_node_pair_trust_receipts_v1_attempt", "node_pair_budget_attempt_insert_v1", "node_pair_budget_attempt_update_v1", "node_pair_budget_attempt_delete_v1", "node_pair_budget_receipt_insert_v1", "node_pair_budget_read_insert_v1", "node_pair_budget_read_delete_v1", "hub_app_node_grants_v1_pair_candidate"}

const nodePairTrustApprovalReserveBytes = 12 << 20

const nodePairTrustBudgetSQL = `
CREATE TABLE hub_node_pair_trust_budget_v1(id INTEGER PRIMARY KEY CHECK(id=1),anonymous_rows INTEGER NOT NULL DEFAULT 0,anonymous_bytes INTEGER NOT NULL DEFAULT 0,read_rows INTEGER NOT NULL DEFAULT 0,read_bytes INTEGER NOT NULL DEFAULT 0,critical_rows INTEGER NOT NULL DEFAULT 0,critical_bytes INTEGER NOT NULL DEFAULT 0,reserved_bytes INTEGER NOT NULL DEFAULT 0,CONSTRAINT node_pair_budget CHECK(anonymous_rows BETWEEN 0 AND 512 AND anonymous_bytes BETWEEN 0 AND 16777216 AND read_rows BETWEEN 0 AND 4096 AND read_bytes BETWEEN 0 AND 16777216 AND critical_rows BETWEEN 0 AND 100000 AND critical_bytes>=0 AND reserved_bytes>=0 AND critical_bytes+reserved_bytes<=268435456));
INSERT INTO hub_node_pair_trust_budget_v1(id) VALUES(1);
CREATE TABLE hub_node_pair_trust_reads_v1(sender_key_id TEXT NOT NULL,request_id TEXT NOT NULL,attempt_id TEXT NOT NULL,operation TEXT NOT NULL,request_digest TEXT NOT NULL,state TEXT NOT NULL,response_packet BLOB NOT NULL CHECK(length(response_packet)>0 AND length(response_packet)<=3145728),created_at TEXT NOT NULL,expires_at TEXT NOT NULL,PRIMARY KEY(sender_key_id,request_id));
CREATE INDEX hub_node_pair_trust_reads_v1_expiry ON hub_node_pair_trust_reads_v1(expires_at);
CREATE INDEX hub_node_pair_trust_reads_v1_attempt ON hub_node_pair_trust_reads_v1(attempt_id);
CREATE TABLE hub_node_pair_trust_rates_v1(attempt_id TEXT NOT NULL,sender_key_id TEXT NOT NULL,window_start TEXT NOT NULL,requests INTEGER NOT NULL CHECK(requests BETWEEN 1 AND 60),expires_at TEXT NOT NULL,PRIMARY KEY(attempt_id,sender_key_id));
CREATE INDEX hub_node_pair_trust_rates_v1_expiry ON hub_node_pair_trust_rates_v1(expires_at);
CREATE INDEX hub_node_pair_trust_v1_gc ON hub_node_pair_trust_v1(authorized,gc_after);
CREATE INDEX hub_app_node_grants_v1_pair_candidate ON hub_app_node_grants_v1(json_extract(claims_json,'$.candidate.request_id'));
CREATE INDEX node_control_pair_trust_gc_v1 ON node_control_key_requests_v1(state,expires_at);
CREATE INDEX hub_node_pair_trust_receipts_v1_attempt ON hub_node_pair_trust_receipts_v1(attempt_id,operation);
CREATE TRIGGER node_control_pair_trust_required_no_delete_v1 BEFORE DELETE ON node_control_key_requests_v1 WHEN OLD.require_pair_trust_ack=1 AND NOT EXISTS(SELECT 1 FROM hub_node_pair_trust_v1 a WHERE a.candidate_request_id=OLD.id AND a.authorized=0 AND a.state IN('EXPIRED','CANCELLED','FENCED')) BEGIN SELECT RAISE(ABORT,'ACK-gated candidate history cannot lose its independent marker');END;
CREATE TRIGGER node_pair_budget_attempt_insert_v1 AFTER INSERT ON hub_node_pair_trust_v1 BEGIN UPDATE hub_node_pair_trust_budget_v1 SET anonymous_rows=anonymous_rows+1,anonymous_bytes=anonymous_bytes+length(CAST(NEW.context_json AS BLOB))+length(CAST(NEW.record_json AS BLOB)) WHERE id=1;END;
CREATE TRIGGER node_pair_budget_attempt_update_v1 AFTER UPDATE ON hub_node_pair_trust_v1 BEGIN UPDATE hub_node_pair_trust_budget_v1 SET anonymous_rows=anonymous_rows+CASE WHEN OLD.authorized=0 AND NEW.authorized=1 THEN -1 ELSE 0 END,anonymous_bytes=anonymous_bytes+CASE WHEN OLD.authorized=0 AND NEW.authorized=0 THEN length(CAST(NEW.record_json AS BLOB))-length(CAST(OLD.record_json AS BLOB)) WHEN OLD.authorized=0 AND NEW.authorized=1 THEN -length(CAST(OLD.record_json AS BLOB))-length(CAST(OLD.context_json AS BLOB)) ELSE 0 END,critical_bytes=critical_bytes+CASE WHEN OLD.authorized=0 AND NEW.authorized=1 THEN length(CAST(NEW.record_json AS BLOB))+length(CAST(NEW.context_json AS BLOB)) WHEN OLD.authorized=1 THEN length(CAST(NEW.record_json AS BLOB))-length(CAST(OLD.record_json AS BLOB)) ELSE 0 END,reserved_bytes=reserved_bytes+NEW.reserved_bytes-OLD.reserved_bytes WHERE id=1;END;
CREATE TRIGGER node_pair_budget_attempt_delete_v1 AFTER DELETE ON hub_node_pair_trust_v1 BEGIN UPDATE hub_node_pair_trust_budget_v1 SET anonymous_rows=anonymous_rows-1,anonymous_bytes=anonymous_bytes-length(CAST(OLD.record_json AS BLOB))-length(CAST(OLD.context_json AS BLOB)) WHERE id=1;END;
CREATE TRIGGER node_pair_budget_receipt_insert_v1 AFTER INSERT ON hub_node_pair_trust_receipts_v1 BEGIN UPDATE hub_node_pair_trust_budget_v1 SET critical_rows=critical_rows+1,critical_bytes=critical_bytes+length(NEW.response_packet) WHERE id=1;END;
CREATE TRIGGER node_pair_budget_read_insert_v1 AFTER INSERT ON hub_node_pair_trust_reads_v1 BEGIN UPDATE hub_node_pair_trust_budget_v1 SET read_rows=read_rows+1,read_bytes=read_bytes+length(NEW.response_packet) WHERE id=1;END;
CREATE TRIGGER node_pair_budget_read_delete_v1 AFTER DELETE ON hub_node_pair_trust_reads_v1 BEGIN UPDATE hub_node_pair_trust_budget_v1 SET read_rows=read_rows-1,read_bytes=read_bytes-length(OLD.response_packet) WHERE id=1;END;
`

func nodePairGC(tx *sql.Tx, at time.Time) error {
	stamp := appNodeStamp(at)
	for _, query := range []string{
		`DELETE FROM hub_node_pair_trust_reads_v1 WHERE rowid IN(SELECT rowid FROM hub_node_pair_trust_reads_v1 WHERE expires_at<=? ORDER BY expires_at LIMIT 256)`,
		`DELETE FROM hub_node_pair_trust_rates_v1 WHERE rowid IN(SELECT rowid FROM hub_node_pair_trust_rates_v1 WHERE expires_at<=? ORDER BY expires_at LIMIT 256)`,
	} {
		if _, err := tx.Exec(query, stamp); err != nil {
			return err
		}
	}
	rows, err := tx.Query(`SELECT attempt_id FROM hub_node_pair_trust_v1 WHERE authorized=0 AND gc_after<=? ORDER BY gc_after LIMIT 256`, stamp)
	if err != nil {
		return err
	}
	var ids []string
	for rows.Next() {
		var id string
		if rows.Scan(&id) != nil {
			rows.Close()
			return ErrNodePairTrustRejected
		}
		ids = append(ids, id)
	}
	err = rows.Err()
	rows.Close()
	if err != nil {
		return err
	}
	for _, id := range ids {
		r, err := nodePairLoad(tx, id)
		if err != nil {
			return err
		}
		if r.Approval != nil {
			continue
		}
		if err = nodePairExpire(tx, r, wire.NodePairTrustExpired, at); err != nil {
			return err
		}
		if _, err = tx.Exec(`DELETE FROM node_control_key_requests_v1 WHERE id=(SELECT candidate_request_id FROM hub_node_pair_trust_v1 WHERE attempt_id=? AND authorized=0) AND state IN('PENDING','EXPIRED','CANCELLED')`, id); err != nil {
			return err
		}
		if _, err = tx.Exec(`DELETE FROM hub_node_pair_trust_v1 WHERE attempt_id=? AND authorized=0`, id); err != nil {
			return err
		}
	}
	// The unchanged old INITIAL service also has unauthenticated candidates.
	// Confirmed/Owner-authorized history and marked missing-side rows are exempt.
	_, err = tx.Exec(`DELETE FROM node_control_key_requests_v1 WHERE id IN(SELECT id FROM node_control_key_requests_v1 WHERE require_pair_trust_ack=0 AND state IN('PENDING','EXPIRED','CANCELLED') AND NOT EXISTS(SELECT 1 FROM hub_app_node_grants_v1 g WHERE json_extract(g.claims_json,'$.candidate.request_id')=node_control_key_requests_v1.id) AND expires_at<=? AND cicada_network_expiry_allows(expires_at,?)=0 ORDER BY expires_at LIMIT 256)`, appNodeStamp(at.Add(-10*time.Minute)), appNodeStamp(at.Add(-10*time.Minute)))
	return err
}

func nodePairReadRate(tx *sql.Tx, h wire.NodePairTrustPacket, at time.Time) error {
	var start string
	var count int
	err := tx.QueryRow(`SELECT window_start,requests FROM hub_node_pair_trust_rates_v1 WHERE attempt_id=? AND sender_key_id=?`, h.AttemptID, h.SenderPublic.ID).Scan(&start, &count)
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		return err
	}
	window, e := time.Parse(time.RFC3339Nano, start)
	if e != nil || !at.Before(window.Add(time.Minute)) {
		start = appNodeStamp(at)
		count = 0
	}
	if count >= 60 {
		return ErrNodePairTrustCapacity
	}
	_, err = tx.Exec(`INSERT INTO hub_node_pair_trust_rates_v1(attempt_id,sender_key_id,window_start,requests,expires_at) VALUES(?,?,?,?,?) ON CONFLICT(attempt_id,sender_key_id) DO UPDATE SET window_start=excluded.window_start,requests=excluded.requests,expires_at=excluded.expires_at`, h.AttemptID, h.SenderPublic.ID, start, count+1, appNodeStamp(at.Add(2*time.Minute)))
	return err
}

func nodePairCritical(tx *sql.Tx, in HubNodePairTrustInput, result wire.NodePairTrustResult) bool {
	op := in.Header.Operation
	if result.ErrorCode != "" || op == wire.OperationNodePairTrustReconcile || op == wire.OperationOwnerNodePairTrustLookup || op == wire.OperationOwnerNodePairTrustStatus {
		return false
	}
	r, err := nodePairLoad(tx, in.Header.AttemptID)
	if err != nil || r.Approval == nil {
		return false
	}
	if op == wire.OperationNodePairTrustPoll {
		return result.State == wire.NodePairTrustOwnerApproved
	}
	if op == wire.OperationNodePairTrustCancel || op == wire.OperationOwnerNodePairTrustCancel {
		if result.State != wire.NodePairTrustCancelled {
			return false
		}
		var prior bool
		if tx.QueryRow(`SELECT EXISTS(SELECT 1 FROM hub_node_pair_trust_receipts_v1 WHERE attempt_id=? AND operation IN(?,?))`, in.Header.AttemptID, wire.OperationNodePairTrustCancel, wire.OperationOwnerNodePairTrustCancel).Scan(&prior) != nil {
			return false
		}
		return !prior
	}
	return op == wire.OperationOwnerNodePairTrustPrepare || op == wire.OperationOwnerNodePairTrustComplete || op == wire.OperationNodePairTrustACK
}

func nodePairReadExpiry(tx *sql.Tx, in HubNodePairTrustInput) string {
	end := in.At.Add(2 * time.Minute)
	if in.Header.Operation == wire.OperationNodePairTrustStart || in.Header.Operation == wire.OperationNodePairTrustExisting || in.Header.Operation == wire.OperationNodePairTrustCommit {
		if r, e := nodePairLoad(tx, in.Header.AttemptID); e == nil {
			if expiry, e := time.Parse(time.RFC3339Nano, r.Context.ExpiresAt); e == nil {
				end = expiry.Add(10 * time.Minute)
			}
		}
	}
	return appNodeStamp(end)
}

func nodePairSaveRecordBudget(tx *sql.Tx, r *nodePairTrustRecord, raw []byte, at time.Time) error {
	authorized := 0
	if r.Approval != nil {
		authorized = 1
	}
	terminal := r.State != wire.NodePairTrustPending && r.State != wire.NodePairTrustOwnerApproved && r.State != "ACKING"
	_, err := tx.Exec(`UPDATE hub_node_pair_trust_v1 SET state=?,oob_commitment=?,authorized=?,reserved_bytes=CASE WHEN ? THEN 0 WHEN authorized=1 THEN max(0,reserved_bytes-max(0,?-length(CAST(record_json AS BLOB)))) ELSE reserved_bytes END,record_json=?,updated_at=? WHERE attempt_id=?`, r.State, r.OOB, authorized, terminal, len(raw), string(raw), appNodeStamp(at), r.Context.AttemptID)
	return err
}

func nodePairContextExpiry(c wire.NodePairTrustContext) time.Time {
	t, _ := time.Parse(time.RFC3339Nano, c.ExpiresAt)
	return t
}
