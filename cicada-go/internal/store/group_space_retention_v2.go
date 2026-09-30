package store

import (
	"database/sql"
	"time"
)

// PurgeExpiredGroupSpaces removes ciphertext and public key snapshots after
// retention. It keeps only a bounded-lifetime ID/sequence tombstone so a
// missing reference is explainable without keeping body or reader metadata.
func (s *Store) PurgeExpiredGroupSpaces(limit int) (int, error) {
	if limit <= 0 || limit > GroupSpaceMaxPage {
		limit = GroupSpaceMaxPage
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	tx, err := s.db.Begin()
	if err != nil {
		return 0, err
	}
	defer tx.Rollback()
	count, err := purgeExpiredGroupSpacesTx(tx, time.Now().UTC(), limit)
	if err != nil {
		return 0, err
	}
	if err := tx.Commit(); err != nil {
		return 0, err
	}
	return count, nil
}

func purgeExpiredGroupSpacesTx(tx *sql.Tx, at time.Time, limit int) (int, error) {
	nowText := at.Format(time.RFC3339Nano)
	rows, err := tx.Query(`SELECT record_id,hub_id,network_id,group_id,
producer_endpoint_id,kind,operation_id,seq,state FROM group_space_records_v2
WHERE (state='PREPARED' AND cicada_network_expiry_allows(reservation_expires_at,?)=0)
 OR (state='COMMITTED' AND cicada_network_expiry_allows(expires_at,?)=0)
ORDER BY seq LIMIT ?`, nowText, nowText, limit)
	if err != nil {
		return 0, err
	}
	type expired struct {
		id, hubID, networkID, groupID, producerID, kind, operationID, state string
		seq                                                                 int64
	}
	var records []expired
	for rows.Next() {
		var row expired
		if err := rows.Scan(&row.id, &row.hubID, &row.networkID, &row.groupID,
			&row.producerID, &row.kind, &row.operationID, &row.seq, &row.state); err != nil {
			rows.Close()
			return 0, err
		}
		records = append(records, row)
	}
	err = rows.Err()
	rows.Close()
	if err != nil {
		return 0, err
	}
	for _, row := range records {
		if row.state == "COMMITTED" {
			if _, err := tx.Exec(`INSERT OR IGNORE INTO group_space_tombstones_v2
(record_id,hub_id,network_id,group_id,producer_endpoint_id,kind,operation_id,seq,expired_at,purged_at)
VALUES(?,?,?,?,?,?,?,?,?,?)`, row.id, row.hubID, row.networkID, row.groupID,
				row.producerID, row.kind, row.operationID, row.seq, nowText, nowText); err != nil {
				return 0, err
			}
		}
		if _, err := tx.Exec(`DELETE FROM group_space_history_grants_v2 WHERE record_id=?`, row.id); err != nil {
			return 0, err
		}
		if _, err := tx.Exec(`DELETE FROM group_space_history_manifests_v2 WHERE record_id=?`, row.id); err != nil {
			return 0, err
		}
		if _, err := tx.Exec(`DELETE FROM group_space_readers_v2 WHERE record_id=?`, row.id); err != nil {
			return 0, err
		}
		if _, err := tx.Exec(`DELETE FROM group_space_topics_v2 WHERE topic_id=?`, row.id); err != nil {
			return 0, err
		}
		if _, err := tx.Exec(`DELETE FROM group_space_records_v2 WHERE record_id=?`, row.id); err != nil {
			return 0, err
		}
	}
	// The tombstone preserves retry conflict only for a bounded post-retention
	// window. Under churn, discard the oldest IDs rather than accumulating
	// unlimited public metadata for an otherwise lightweight Space.
	groups := map[string]struct{}{}
	for _, row := range records {
		if row.state == "COMMITTED" {
			groups[row.groupID] = struct{}{}
		}
	}
	for groupID := range groups {
		var total int
		if err := tx.QueryRow(`SELECT COUNT(*) FROM group_space_tombstones_v2 WHERE group_id=?`, groupID).Scan(&total); err != nil {
			return 0, err
		}
		if total > groupSpaceTombstoneQuota {
			if _, err := tx.Exec(`DELETE FROM group_space_tombstones_v2 WHERE record_id IN
(SELECT record_id FROM group_space_tombstones_v2 WHERE group_id=? ORDER BY purged_at,seq LIMIT ?)`,
				groupID, total-groupSpaceTombstoneQuota); err != nil {
				return 0, err
			}
		}
	}
	cutoff := at.Add(-GroupSpaceMaxRetention).Format(time.RFC3339Nano)
	if _, err := tx.Exec(`DELETE FROM group_space_history_manifests_v2 WHERE manifest_id IN
(SELECT h.manifest_id FROM group_space_history_manifests_v2 h
WHERE cicada_network_expiry_allows(h.expires_at,?)=0
AND NOT EXISTS(SELECT 1 FROM group_space_history_grants_v2 g WHERE g.manifest_id=h.manifest_id)
ORDER BY h.expires_at LIMIT ?)`, nowText, limit); err != nil {
		return 0, err
	}
	if _, err := tx.Exec(`DELETE FROM group_space_tombstones_v2 WHERE record_id IN
(SELECT record_id FROM group_space_tombstones_v2
WHERE cicada_network_expiry_allows(purged_at,?)=0 ORDER BY purged_at LIMIT ?)`, cutoff, limit); err != nil {
		return 0, err
	}
	return len(records), nil
}
