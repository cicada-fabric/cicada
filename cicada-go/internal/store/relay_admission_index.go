package store

import (
	"database/sql"
	"database/sql/driver"
	"encoding/binary"
	"fmt"
	"strings"
	"time"

	"modernc.org/sqlite"
)

const (
	relayAskExpiryOrderKeyFunction = "cicada_relay_expiry_order_key_v1"
	relayAskExpiryOrderIndex       = "relay_v2_requests_pending_expiry_order_v1_idx"
	relayAskExpiryOrderMigrationID = "v2.relay.ask_expiry_order_index"
)

const relayAskExpiryOrderIndexDDL = `CREATE INDEX ` + relayAskExpiryOrderIndex + `
ON relay_v2_requests (state, ` + relayAskExpiryOrderKeyFunction + `(expires_at))`

const relayAskExpiryOrderIndexCreateDDL = `CREATE INDEX IF NOT EXISTS ` + relayAskExpiryOrderIndex + `
ON relay_v2_requests (state, ` + relayAskExpiryOrderKeyFunction + `(expires_at))`

var relayUnboundedExpiryOrderKey = []byte{
	0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
	0xff, 0xff, 0xff, 0xff,
}

func init() {
	// This expression is part of the v59 SQLite index definition. Keep v1
	// semantics fixed forever; a change requires a new function/index version
	// and a migration that rebuilds the index.
	sqlite.MustRegisterDeterministicScalarFunction(relayAskExpiryOrderKeyFunction, 1,
		func(_ *sqlite.FunctionContext, args []driver.Value) (driver.Value, error) {
			value, ok := args[0].(string)
			if !ok {
				return nil, nil
			}
			key := relayAskExpiryOrderKey(value)
			if key == nil {
				return nil, nil
			}
			return key, nil
		})
}

// relayAskExpiryOrderKey returns a lexicographically ordered, 12-byte BLOB
// for a valid RFC3339Nano instant. Blank expiry uses the maximum key so it is
// unlimited; malformed persisted timestamps are NULL and remain excluded.
func relayAskExpiryOrderKey(value string) []byte {
	if value == "" {
		return append([]byte(nil), relayUnboundedExpiryOrderKey...)
	}
	parsed, err := time.Parse(time.RFC3339Nano, value)
	if err != nil {
		return nil
	}
	return relayAskExpiryOrderKeyTime(parsed)
}

func relayAskExpiryOrderKeyTime(value time.Time) []byte {
	key := make([]byte, 12)
	// Flipping the sign bit maps signed Unix seconds to unsigned big-endian
	// order. RFC3339's four-digit year range is far inside int64 seconds, so this
	// avoids UnixNano's narrower range without losing nanosecond precision.
	seconds := uint64(value.Unix()) ^ (uint64(1) << 63)
	binary.BigEndian.PutUint64(key[:8], seconds)
	binary.BigEndian.PutUint32(key[8:], uint32(value.Nanosecond()))
	return key
}

func relayAskExpiryCutoff(currentTime string) ([]byte, bool) {
	parsed, err := time.Parse(time.RFC3339Nano, currentTime)
	if err != nil {
		return nil, false
	}
	return relayAskExpiryOrderKeyTime(parsed), true
}

func relayPendingAskCountSQL(scope string) (string, bool) {
	query := `SELECT count(*) FROM relay_v2_requests INDEXED BY ` + relayAskExpiryOrderIndex + `
WHERE state IN (?, ?) AND ` + relayAskExpiryOrderKeyFunction + `(expires_at) > ?`
	switch scope {
	case RelayAdmissionScopeSenderPrincipal:
		return query + ` AND sender_principal_id = ?`, true
	case RelayAdmissionScopeSenderEndpoint:
		return query + ` AND sender_endpoint_id = ?`, true
	case RelayAdmissionScopeSenderGroup:
		return query + ` AND sender_group_id = ?`, true
	case RelayAdmissionScopeReceiver:
		return query + ` AND receiver_endpoint_id = ?`, true
	case RelayAdmissionScopeGlobal:
		return query, true
	default:
		return "", false
	}
}

func (s *Store) initializeRelayAskExpiryOrderIndex() error {
	_, err := s.db.Exec(relayAskExpiryOrderIndexCreateDDL)
	return err
}

func verifyRelayAskExpiryOrderIndex(db *sql.DB) error {
	var kind, table, statement string
	if err := db.QueryRow(`SELECT type, tbl_name, sql FROM sqlite_master WHERE name = ?`,
		relayAskExpiryOrderIndex).Scan(&kind, &table, &statement); err != nil {
		return fmt.Errorf("inspect Relay Ask expiry index: %w", err)
	}
	if kind != "index" || table != "relay_v2_requests" || normalizeRelayIndexSQL(statement) != normalizeRelayIndexSQL(relayAskExpiryOrderIndexDDL) {
		return fmt.Errorf("Relay Ask expiry index definition mismatch: type=%q table=%q", kind, table)
	}
	return nil
}

func normalizeRelayIndexSQL(statement string) string {
	normalized := strings.Join(strings.Fields(strings.ToLower(statement)), " ")
	return strings.Replace(normalized, "create index if not exists ", "create index ", 1)
}
