package store

import (
	"database/sql"
	"errors"
	"sort"
	"time"
)

const (
	userMonitorBroadcastV2MaxLivePreviewsPerDevice = 16
	userMonitorBroadcastV2MaxLivePreviewsPerOwner  = 64
	userMonitorBroadcastV2NoticeScanPage           = 16
)

// ErrUserMonitorBroadcastV2Backpressure deliberately does not reveal whether
// the owner-wide or device-specific intake limit was reached.
var ErrUserMonitorBroadcastV2Backpressure = errors.New("user-through-Monitor broadcast intake is temporarily busy")

// initializeUserMonitorBroadcastV2LimitsSchema adds bounded admission indexes
// and a durable scheduling cursor for Node notice scans. The cursor is only a
// fairness hint; notification and delivery authorization always re-run Guard.
func (s *Store) initializeUserMonitorBroadcastV2LimitsSchema() error {
	_, err := s.db.Exec(`CREATE TABLE IF NOT EXISTS user_monitor_broadcast_v2_notice_cursors (
 node_id TEXT PRIMARY KEY,
 owner_id TEXT NOT NULL,
 last_expiry_julian REAL NOT NULL,
 last_preview_id TEXT NOT NULL,
 updated_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS user_monitor_broadcast_v2_live_device_expiry_idx
 ON user_monitor_broadcast_v2(owner_id,device_id,status,julianday(expires_at))
 WHERE status IN ('PREPARED','APPROVED','DISPATCH_AUTHORIZED');
CREATE INDEX IF NOT EXISTS user_monitor_broadcast_v2_live_owner_expiry_idx
 ON user_monitor_broadcast_v2(owner_id,status,julianday(expires_at))
 WHERE status IN ('PREPARED','APPROVED','DISPATCH_AUTHORIZED');
CREATE INDEX IF NOT EXISTS user_monitor_broadcast_v2_notice_scan_idx
 ON user_monitor_broadcast_v2(owner_id,status,julianday(expires_at),preview_id)
 WHERE status IN ('APPROVED','DISPATCH_AUTHORIZED');
DROP INDEX IF EXISTS user_monitor_broadcast_v2_active_notice_idx;`)
	return err
}

// checkUserMonitorBroadcastV2IntakeTx is called only after exact prepare
// request retries have been resolved. The indexed OFFSET probes stop at the
// limit instead of counting all historical or expired ledger rows.
func checkUserMonitorBroadcastV2IntakeTx(tx *sql.Tx, ownerID, deviceID string, nowTime time.Time) error {
	nowText := nowTime.UTC().Format(time.RFC3339Nano)
	var overDeviceLimit int
	err := tx.QueryRow(`SELECT 1 FROM user_monitor_broadcast_v2 INDEXED BY user_monitor_broadcast_v2_live_device_expiry_idx
WHERE owner_id=? AND device_id=?
 AND status IN ('PREPARED','APPROVED','DISPATCH_AUTHORIZED')
 AND julianday(expires_at)>julianday(?)
LIMIT 1 OFFSET ?`, ownerID, deviceID, nowText,
		userMonitorBroadcastV2MaxLivePreviewsPerDevice-1).Scan(&overDeviceLimit)
	if err == nil {
		return ErrUserMonitorBroadcastV2Backpressure
	}
	if !errors.Is(err, sql.ErrNoRows) {
		return err
	}

	var overOwnerLimit int
	err = tx.QueryRow(`SELECT 1 FROM user_monitor_broadcast_v2 INDEXED BY user_monitor_broadcast_v2_live_owner_expiry_idx
WHERE owner_id=?
 AND status IN ('PREPARED','APPROVED','DISPATCH_AUTHORIZED')
 AND julianday(expires_at)>julianday(?)
LIMIT 1 OFFSET ?`, ownerID, nowText,
		userMonitorBroadcastV2MaxLivePreviewsPerOwner-1).Scan(&overOwnerLimit)
	if err == nil {
		return ErrUserMonitorBroadcastV2Backpressure
	}
	if !errors.Is(err, sql.ErrNoRows) {
		return err
	}
	return nil
}

type userMonitorBroadcastV2NoticeCursor struct {
	ownerID      string
	expiryJulian float64
	previewID    string
}

type userMonitorBroadcastV2NoticeCandidate struct {
	previewID    string
	expiryJulian float64
	sourceNodeID string
	receiptState string
}

func readUserMonitorBroadcastV2NoticeCandidatesTx(tx *sql.Tx, ownerID, nowText string,
	cursor *userMonitorBroadcastV2NoticeCursor, after bool, limit int) ([]userMonitorBroadcastV2NoticeCandidate, error) {
	if limit <= 0 {
		return nil, nil
	}
	results := make([]userMonitorBroadcastV2NoticeCandidate, 0, limit*2)
	statuses := [...]string{UserMonitorBroadcastV2Approved, UserMonitorBroadcastV2DispatchAuthorized}
	for _, status := range statuses {
		query := `SELECT ledger.preview_id,julianday(ledger.expires_at),snap.source_node_id,
COALESCE(receipt.receipt_state,'')
FROM user_monitor_broadcast_v2 ledger INDEXED BY user_monitor_broadcast_v2_notice_scan_idx
JOIN group_broadcast_v2_snapshots snap ON snap.broadcast_id=ledger.broadcast_id
LEFT JOIN user_monitor_broadcast_v2_notice_receipts receipt ON receipt.preview_id=ledger.preview_id
WHERE ledger.owner_id=? AND ledger.status=?
 AND ledger.status IN ('APPROVED','DISPATCH_AUTHORIZED')
 AND julianday(ledger.expires_at)>julianday(?)`
		args := []any{ownerID, status, nowText}
		if cursor != nil {
			comparison := ">"
			if !after {
				// Include the current cursor at wrap. The last examined notice is
				// still pending until receipt state advances, so a lost list response
				// must not make that one item disappear permanently.
				comparison = "<="
			}
			query += ` AND (julianday(ledger.expires_at),ledger.preview_id) ` + comparison + ` (?,?)`
			args = append(args, cursor.expiryJulian, cursor.previewID)
		}
		query += ` ORDER BY julianday(ledger.expires_at),ledger.preview_id LIMIT ?`
		args = append(args, limit)
		rows, err := tx.Query(query, args...)
		if err != nil {
			return nil, err
		}
		for rows.Next() {
			var item userMonitorBroadcastV2NoticeCandidate
			if err := rows.Scan(&item.previewID, &item.expiryJulian, &item.sourceNodeID, &item.receiptState); err != nil {
				rows.Close()
				return nil, err
			}
			results = append(results, item)
		}
		if err := rows.Err(); err != nil {
			rows.Close()
			return nil, err
		}
		if err := rows.Close(); err != nil {
			return nil, err
		}
	}
	sort.Slice(results, func(i, j int) bool {
		if results[i].expiryJulian != results[j].expiryJulian {
			return results[i].expiryJulian < results[j].expiryJulian
		}
		return results[i].previewID < results[j].previewID
	})
	if len(results) > limit {
		results = results[:limit]
	}
	return results, nil
}

func readUserMonitorBroadcastV2NoticeCursorTx(tx *sql.Tx, nodeID, ownerID string) (userMonitorBroadcastV2NoticeCursor, bool, error) {
	var cursor userMonitorBroadcastV2NoticeCursor
	err := tx.QueryRow(`SELECT owner_id,last_expiry_julian,last_preview_id
FROM user_monitor_broadcast_v2_notice_cursors WHERE node_id=?`, nodeID).
		Scan(&cursor.ownerID, &cursor.expiryJulian, &cursor.previewID)
	if errors.Is(err, sql.ErrNoRows) {
		return userMonitorBroadcastV2NoticeCursor{}, false, nil
	}
	if err != nil {
		return userMonitorBroadcastV2NoticeCursor{}, false, err
	}
	if cursor.ownerID != ownerID {
		return userMonitorBroadcastV2NoticeCursor{}, false, nil
	}
	return cursor, true, nil
}

func writeUserMonitorBroadcastV2NoticeCursorTx(tx *sql.Tx, nodeID, ownerID string,
	cursor userMonitorBroadcastV2NoticeCursor, nowTime time.Time) error {
	_, err := tx.Exec(`INSERT INTO user_monitor_broadcast_v2_notice_cursors
(node_id,owner_id,last_expiry_julian,last_preview_id,updated_at) VALUES(?,?,?,?,?)
ON CONFLICT(node_id) DO UPDATE SET owner_id=excluded.owner_id,
 last_expiry_julian=excluded.last_expiry_julian,last_preview_id=excluded.last_preview_id,
 updated_at=excluded.updated_at`, nodeID, ownerID, cursor.expiryJulian, cursor.previewID,
		nowTime.UTC().Format(time.RFC3339Nano))
	return err
}
