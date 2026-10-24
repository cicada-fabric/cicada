package store

// Schema 68 is compatible only before Node pairing trust has any state. This
// deliberately does not review recovery of reservations, capsules or receipts.
// A full NPT restore review must define their forward and UNKNOWN semantics.
var hubRestoreNPTTables = []string{
	"hub_node_pair_trust_v1", "hub_node_pair_trust_receipts_v1", "hub_node_pair_trust_slots_v1",
	"hub_node_pair_trust_reads_v1", "hub_node_pair_trust_rates_v1", "hub_node_pair_trust_budget_v1",
}

func hubRestoreNPTTable(name string) bool {
	for _, table := range hubRestoreNPTTables {
		if name == table {
			return true
		}
	}
	return false
}
func hubRestoreSchemaAllowed(cp *HubRestoreCheckpoint) bool {
	if cp == nil {
		return false
	}
	if cp.SchemaVersion == hubRestoreReviewedSchemaVersion {
		return true
	}
	if cp.SchemaVersion != 68 {
		return false
	}
	for _, name := range hubRestoreNPTTables {
		rows, ok := cp.rows[name]
		if !ok {
			return false
		}
		if name != "hub_node_pair_trust_budget_v1" {
			if len(rows) != 0 {
				return false
			}
			continue
		}
		if len(rows) != 1 {
			return false
		}
		for _, row := range rows {
			if len(row) != 8 || row["id"] != int64(1) {
				return false
			}
			for _, field := range []string{"anonymous_rows", "anonymous_bytes", "read_rows", "read_bytes", "critical_rows", "critical_bytes", "reserved_bytes"} {
				if row[field] != int64(0) {
					return false
				}
			}
		}
	}
	rows, ok := cp.rows["node_control_key_requests_v1"]
	if !ok {
		return false
	}
	for _, row := range rows {
		if row["require_pair_trust_ack"] != int64(0) {
			return false
		}
	}
	return true
}
