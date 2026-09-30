package store

import (
	"database/sql"
	"strings"
	"time"
)

// Hints deliberately contain neither record identifiers nor encrypted bodies.
// An Endpoint fetches a record through ListGroupSpace and its fresh Guard.
type GroupSpaceHint struct {
	Sequence int64  `json:"sequence"`
	Class    string `json:"class"`
}

type GroupSpaceSyncInput struct {
	GroupID  string `json:"group_id"`
	AfterSeq int64  `json:"after_seq"`
	Limit    int    `json:"limit,omitempty"`
}

type GroupSpaceSyncResult struct {
	HubID            string           `json:"hub_id"`
	NetworkID        string           `json:"network_id"`
	BindingEpoch     uint64           `json:"binding_epoch"`
	WatermarkVersion string           `json:"watermark_version"`
	GroupID          string           `json:"group_id"`
	NextSeq          int64            `json:"next_seq"`
	LatestSeq        int64            `json:"latest_seq"`
	Hints            []GroupSpaceHint `json:"hints"`
	HasMore          bool             `json:"has_more"`
	ReadSeq          int64            `json:"read_seq"`
	UnreadCount      int              `json:"unread_count"`
}

type GroupSpaceReadStateInput struct {
	GroupID string `json:"group_id"`
}

type GroupSpaceMarkReadInput struct {
	GroupID    string `json:"group_id"`
	ThroughSeq int64  `json:"through_seq"`
}

type GroupSpaceReadState struct {
	GroupID     string `json:"group_id"`
	ReadSeq     int64  `json:"read_seq"`
	LatestSeq   int64  `json:"latest_seq"`
	UnreadCount int    `json:"unread_count"`
}

func (s *Store) initializeGroupSpaceReadStateSchema() error {
	if err := s.ensureColumn("group_space_records_v2", "commit_seq", `ALTER TABLE group_space_records_v2 ADD COLUMN commit_seq INTEGER NOT NULL DEFAULT 0`); err != nil {
		return err
	}
	_, err := s.db.Exec(`CREATE TABLE IF NOT EXISTS group_space_read_state_v2 (
group_id TEXT NOT NULL, endpoint_id TEXT NOT NULL, read_seq INTEGER NOT NULL CHECK(read_seq>=0),
updated_at TEXT NOT NULL, PRIMARY KEY(group_id,endpoint_id)
);
CREATE TABLE IF NOT EXISTS group_space_change_sequences_v2 (
group_id TEXT PRIMARY KEY, next_seq INTEGER NOT NULL CHECK(next_seq>0)
);
CREATE INDEX IF NOT EXISTS group_space_records_commit_v2 ON group_space_records_v2(group_id,commit_seq);`)
	if err != nil {
		return err
	}
	rows, err := s.db.Query(`SELECT record_id,group_id FROM group_space_records_v2
WHERE state='COMMITTED' ORDER BY group_id,committed_at,seq`)
	if err != nil {
		return err
	}
	type oldRecord struct{ id, groupID string }
	var old []oldRecord
	for rows.Next() {
		var record oldRecord
		if err := rows.Scan(&record.id, &record.groupID); err != nil {
			rows.Close()
			return err
		}
		old = append(old, record)
	}
	err = rows.Err()
	rows.Close()
	if err != nil {
		return err
	}
	watermark := make(map[string]int64)
	for _, record := range old {
		watermark[record.groupID]++
		if _, err := s.db.Exec(`UPDATE group_space_records_v2 SET commit_seq=? WHERE record_id=?`,
			watermark[record.groupID], record.id); err != nil {
			return err
		}
	}
	for groupID, latest := range watermark {
		if _, err := s.db.Exec(`INSERT INTO group_space_change_sequences_v2(group_id,next_seq) VALUES(?,?)`,
			groupID, latest+1); err != nil {
			return err
		}
	}
	return nil
}

func groupSpaceLatestSeqTx(tx *sql.Tx, groupID string) (int64, error) {
	var latest int64
	err := tx.QueryRow(`SELECT next_seq-1 FROM group_space_change_sequences_v2
WHERE group_id=?`, groupID).Scan(&latest)
	if err == sql.ErrNoRows {
		return 0, nil
	}
	return latest, err
}

func groupSpaceReadSeqTx(tx *sql.Tx, actor GroupSpaceActor) (int64, error) {
	var from int64
	var active int
	if err := tx.QueryRow(`SELECT read_from_seq,active FROM group_space_audience_v2
WHERE group_id=? AND endpoint_id=? AND principal_id=?`, actor.Scope.GroupID,
		actor.Scope.EndpointID, actor.Scope.PrincipalID).Scan(&from, &active); err != nil || active != 1 {
		return 0, ErrGroupSpaceDenied
	}
	_ = from // signed record sequence remains the history cutoff, not the read cursor.
	readSeq := int64(0)
	var saved int64
	err := tx.QueryRow(`SELECT read_seq FROM group_space_read_state_v2 WHERE group_id=? AND endpoint_id=?`,
		actor.Scope.GroupID, actor.Scope.EndpointID).Scan(&saved)
	if err != nil && err != sql.ErrNoRows {
		return 0, err
	}
	if saved > readSeq {
		readSeq = saved
	}
	return readSeq, nil
}

type groupSpaceHintCandidate struct {
	id    string
	seq   int64
	class string
}

func groupSpaceVisibleCandidatesTx(tx *sql.Tx, actor GroupSpaceActor, at time.Time) ([]groupSpaceHintCandidate, error) {
	rows, err := tx.Query(`SELECT record_id,commit_seq,kind FROM group_space_records_v2
WHERE group_id=? AND state='COMMITTED' AND cicada_network_expiry_allows(expires_at,?)=1
ORDER BY commit_seq LIMIT ?`, actor.Scope.GroupID, at.Format(time.RFC3339Nano), groupSpaceCommittedQuota+1)
	if err != nil {
		return nil, err
	}
	var candidates []groupSpaceHintCandidate
	for rows.Next() {
		var candidate groupSpaceHintCandidate
		if err := rows.Scan(&candidate.id, &candidate.seq, &candidate.class); err != nil {
			rows.Close()
			return nil, err
		}
		candidates = append(candidates, candidate)
	}
	err = rows.Err()
	rows.Close()
	if err != nil {
		return nil, err
	}
	if len(candidates) > groupSpaceCommittedQuota {
		return nil, ErrGroupSpaceLimit
	}
	visible := candidates[:0]
	for _, candidate := range candidates {
		if groupSpaceRecordReadableTx(tx, actor.Scope, candidate.id, at) == nil {
			visible = append(visible, candidate)
		}
	}
	return visible, nil
}

func groupSpaceReadStateTx(tx *sql.Tx, actor GroupSpaceActor, at time.Time) (GroupSpaceReadState, []groupSpaceHintCandidate, error) {
	state := GroupSpaceReadState{GroupID: actor.Scope.GroupID}
	if err := guardGroupSpaceActorTx(tx, actor, "space.read", at); err != nil {
		return state, nil, err
	}
	readSeq, err := groupSpaceReadSeqTx(tx, actor)
	if err != nil {
		return state, nil, err
	}
	latest, err := groupSpaceLatestSeqTx(tx, actor.Scope.GroupID)
	if err != nil {
		return state, nil, err
	}
	visible, err := groupSpaceVisibleCandidatesTx(tx, actor, at)
	if err != nil {
		return state, nil, err
	}
	state.ReadSeq, state.LatestSeq = readSeq, latest
	for _, candidate := range visible {
		if candidate.seq > readSeq {
			state.UnreadCount++
		}
	}
	return state, visible, nil
}

func (s *Store) SyncGroupSpace(actor GroupSpaceActor, in GroupSpaceSyncInput) (*GroupSpaceSyncResult, error) {
	if !validSameGroupSealedV1Token(in.GroupID) || in.GroupID != actor.Scope.GroupID || in.AfterSeq < 0 || in.Limit < 0 {
		return nil, ErrGroupSpaceInvalid
	}
	if in.Limit == 0 || in.Limit > GroupSpaceMaxPage {
		in.Limit = GroupSpaceMaxPage
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	tx, err := s.db.Begin()
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()
	state, visible, err := groupSpaceReadStateTx(tx, actor, time.Now().UTC())
	if err != nil {
		return nil, err
	}
	if in.AfterSeq > state.LatestSeq {
		return nil, ErrGroupSpaceInvalid
	}
	var hubID string
	if err := tx.QueryRow(`SELECT n.hub_id FROM groups g JOIN networks_v2 n ON n.id=g.network_id WHERE g.id=?`,
		in.GroupID).Scan(&hubID); err != nil {
		return nil, ErrGroupSpaceDenied
	}
	result := &GroupSpaceSyncResult{HubID: hubID, NetworkID: actor.Scope.NetworkID,
		BindingEpoch: actor.Scope.BindingEpoch, WatermarkVersion: "commit_v1",
		GroupID: in.GroupID, NextSeq: state.LatestSeq,
		LatestSeq: state.LatestSeq, Hints: []GroupSpaceHint{}, ReadSeq: state.ReadSeq,
		UnreadCount: state.UnreadCount}
	for _, candidate := range visible {
		if candidate.seq <= in.AfterSeq {
			continue
		}
		if len(result.Hints) == in.Limit {
			result.HasMore = true
			result.NextSeq = result.Hints[len(result.Hints)-1].Sequence
			break
		}
		class := "discussion"
		if candidate.class == GroupSpaceKindJournal {
			class = "journal"
		}
		result.Hints = append(result.Hints, GroupSpaceHint{Sequence: candidate.seq, Class: class})
	}
	if err := tx.Commit(); err != nil {
		return nil, err
	}
	return result, nil
}

func (s *Store) GetGroupSpaceReadState(actor GroupSpaceActor, in GroupSpaceReadStateInput) (*GroupSpaceReadState, error) {
	if !validSameGroupSealedV1Token(in.GroupID) || in.GroupID != actor.Scope.GroupID {
		return nil, ErrGroupSpaceInvalid
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	tx, err := s.db.Begin()
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()
	state, _, err := groupSpaceReadStateTx(tx, actor, time.Now().UTC())
	if err != nil {
		return nil, err
	}
	if err := tx.Commit(); err != nil {
		return nil, err
	}
	return &state, nil
}

func (s *Store) MarkGroupSpaceRead(actor GroupSpaceActor, in GroupSpaceMarkReadInput) (*GroupSpaceReadState, error) {
	if !validSameGroupSealedV1Token(in.GroupID) || in.GroupID != actor.Scope.GroupID || in.ThroughSeq < 0 {
		return nil, ErrGroupSpaceInvalid
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	tx, err := s.db.Begin()
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()
	at := time.Now().UTC()
	state, visible, err := groupSpaceReadStateTx(tx, actor, at)
	if err != nil {
		return nil, err
	}
	if in.ThroughSeq > state.LatestSeq || in.ThroughSeq < state.ReadSeq {
		return nil, ErrGroupSpaceConflict
	}
	if in.ThroughSeq > state.ReadSeq {
		_, err = tx.Exec(`INSERT INTO group_space_read_state_v2(group_id,endpoint_id,read_seq,updated_at)
VALUES(?,?,?,?) ON CONFLICT(group_id,endpoint_id) DO UPDATE SET
read_seq=excluded.read_seq,updated_at=excluded.updated_at WHERE read_seq<excluded.read_seq`,
			in.GroupID, actor.Scope.EndpointID, in.ThroughSeq, at.Format(time.RFC3339Nano))
		if err != nil {
			return nil, err
		}
		state.ReadSeq = in.ThroughSeq
		state.UnreadCount = 0
		for _, candidate := range visible {
			if candidate.seq > state.ReadSeq {
				state.UnreadCount++
			}
		}
	}
	if err := tx.Commit(); err != nil {
		return nil, err
	}
	return &state, nil
}

// This scope is used only by the service's post-commit event fan-out. The
// stream transports a generic scheduling hint; this list never goes on wire.
func GroupSpaceReaderNodes(record *GroupSpaceRecord) []string {
	if record == nil {
		return nil
	}
	nodes := make(map[string]bool, len(record.Snapshot.Readers))
	for _, reader := range record.Snapshot.Readers {
		if id := strings.TrimSpace(reader.NodeID); id != "" {
			nodes[id] = true
		}
	}
	result := make([]string, 0, len(nodes))
	for id := range nodes {
		result = append(result, id)
	}
	return result
}
