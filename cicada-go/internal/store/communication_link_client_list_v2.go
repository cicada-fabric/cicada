package store

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"strings"
	"time"
)

type communicationLinkPageCursor struct {
	OwnerID   string `json:"owner_id"`
	CreatedAt string `json:"created_at"`
	LinkID    string `json:"link_id"`
}

// ListCommunicationLinksPageForOwner returns only contracts to which the
// authenticated owner is a party. The cursor is a position, not authority;
// every page repeats the owner predicate and binds the cursor to that owner.
func (s *Store) ListCommunicationLinksPageForOwner(ownerID, cursor string, limit int) ([]CommunicationLink, string, error) {
	ownerID = strings.TrimSpace(ownerID)
	if ownerID == "" {
		return nil, "", ErrCommunicationLinkNotFound
	}
	if limit <= 0 {
		limit = 50
	} else if limit > 100 {
		limit = 100
	}
	var after communicationLinkPageCursor
	if cursor != "" {
		if len(cursor) > 512 {
			return nil, "", errors.New("invalid communication link cursor")
		}
		raw, err := base64.RawURLEncoding.DecodeString(cursor)
		if err != nil || json.Unmarshal(raw, &after) != nil || after.OwnerID != ownerID ||
			!strings.HasPrefix(after.LinkID, "link_") || len(after.LinkID) > 256 {
			return nil, "", errors.New("invalid communication link cursor")
		}
		if _, err := time.Parse(time.RFC3339Nano, after.CreatedAt); err != nil {
			return nil, "", errors.New("invalid communication link cursor")
		}
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	query := `SELECT ` + communicationLinkColumns + ` FROM communication_links_v2
WHERE (source_owner_id = ? OR target_owner_id = ?)`
	args := []any{ownerID, ownerID}
	if cursor != "" {
		query += ` AND (created_at < ? OR (created_at = ? AND id < ?))`
		args = append(args, after.CreatedAt, after.CreatedAt, after.LinkID)
	}
	query += ` ORDER BY created_at DESC, id DESC LIMIT ?`
	args = append(args, limit+1)
	rows, err := s.db.Query(query, args...)
	if err != nil {
		return nil, "", err
	}
	defer rows.Close()
	items := make([]CommunicationLink, 0, limit)
	for rows.Next() {
		link, err := scanCommunicationLink(rows)
		if err != nil {
			return nil, "", err
		}
		items = append(items, *link)
	}
	if err := rows.Err(); err != nil {
		return nil, "", err
	}
	if len(items) <= limit {
		return items, "", nil
	}
	items = items[:limit]
	last := items[len(items)-1]
	encoded, err := json.Marshal(communicationLinkPageCursor{OwnerID: ownerID, CreatedAt: last.CreatedAt, LinkID: last.ID})
	if err != nil {
		return nil, "", err
	}
	return items, base64.RawURLEncoding.EncodeToString(encoded), nil
}
