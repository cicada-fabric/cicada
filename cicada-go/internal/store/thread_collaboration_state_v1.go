package store

import (
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	wire "github.com/cicada-ai/cicada/internal/hubaccountwire"
)

func threadCollaborationSource(r *hubEndpointGroupsRegistration) wire.ThreadRegistrationSource {
	a := r.anchor.Registration
	// Same actual Thread remains stable through workspace, account, Principal,
	// key or Endpoint changes. Hub scoping keeps this from becoming a global ID.
	raw, _ := json.Marshal([]string{r.hub.HubID, a.Harness, a.NativeSessionID})
	h := sha256.Sum256(append([]byte("cicada/hub-thread-source/v1\x00"), raw...))
	return wire.ThreadRegistrationSource{RegistrationID: hex.EncodeToString(h[:]), SourceEpoch: r.anchor.RegistrationRevision}
}
func threadCollaborationScopeTx(tx *sql.Tx, r *hubEndpointGroupsRegistration, at time.Time) (wire.ThreadScopeView, error) {
	a := r.anchor
	v := wire.ThreadScopeView{Format: wire.ThreadScopeFormat, HubID: r.hub.HubID, NetworkID: a.NetworkID, NodeID: a.Registration.NodeID, EndpointID: a.Registration.EndpointID, Source: threadCollaborationSource(r), RegistrationDigest: a.RegistrationDigest, ScopeRevision: a.RegistrationRevision, RelationsRevision: r.listing, State: "CLASSIFICATION_REQUIRED", ActiveGroupIDs: []string{}, HistoryCoverage: "CICADA_KNOWN_ONLY"}
	var count, networks uint64
	if err := tx.QueryRow(`SELECT count(*),count(DISTINCT network_id) FROM hub_endpoint_groups_registrations_v1 WHERE json_extract(anchor_json,'$.registration.harness')=? AND json_extract(anchor_json,'$.registration.native_session_id')=?`, a.Registration.Harness, a.Registration.NativeSessionID).Scan(&count, &networks); err != nil {
		return v, err
	}
	if count != 1 {
		kind := "UNRESOLVED_HISTORY"
		if networks > 1 {
			kind = "MULTIPLE_NETWORKS"
		}
		v = wire.ThreadScopeView{Format: wire.ThreadScopeFormat, NodeID: a.Registration.NodeID, ScopeRevision: count, State: "NETWORK_CONFLICT", ActiveGroupIDs: []string{}, HistoryCoverage: "CICADA_KNOWN_ONLY", Conflict: &wire.ThreadNetworkConflict{Kind: kind, KnownNetworkCount: networks}}
		return v, wire.ValidateThreadScopeView(v)
	}
	err := tx.QueryRow(`SELECT classification,revision FROM thread_classifications_v1 WHERE registration_id=? AND source_epoch=? AND endpoint_id=? AND owner_id=? AND node_id=? AND network_id=?`, v.Source.RegistrationID, v.Source.SourceEpoch, v.EndpointID, a.Registration.OwnerID, v.NodeID, v.NetworkID).Scan(&v.Classification, &v.ClassificationRevision)
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		return v, err
	}
	cards, err := endpointGroupsRelationCardsTx(tx, r, at)
	if err != nil {
		return v, err
	}
	for _, c := range cards {
		if c.State == "ACTIVE" {
			v.ActiveGroupCount++
			if len(v.ActiveGroupIDs) < wire.MaxThreadCollaborationPageRows {
				v.ActiveGroupIDs = append(v.ActiveGroupIDs, c.GroupID)
			}
		}
	}
	if v.ActiveGroupCount > uint64(len(v.ActiveGroupIDs)) {
		v.GroupsCursor = endpointGroupsPageCursor(v.Source.RegistrationID, fmt.Sprint(v.RelationsRevision), v.ActiveGroupIDs[len(v.ActiveGroupIDs)-1])
	}
	if v.Classification != "" {
		v.State = "CURRENT"
		if v.Classification == wire.ThreadClassificationWorker && v.ActiveGroupCount > 1 {
			v.State = "GROUP_CONFLICT"
		}
	}
	return v, wire.ValidateThreadScopeView(v)
}
func threadCollaborationGuardTx(tx *sql.Tx, r *hubEndpointGroupsRegistration, group string, at time.Time) (wire.GroupLockHolder, error) {
	var empty wire.GroupLockHolder
	if endpointGroupsRegistrationLeaseTx(tx, r, at) != nil {
		return empty, errors.New(wire.ThreadCollaborationErrorAuthorizationRequired)
	}
	scope, err := threadCollaborationScopeTx(tx, r, at)
	if err != nil {
		return empty, err
	}
	if scope.State == "CLASSIFICATION_REQUIRED" {
		return empty, errors.New(wire.ThreadCollaborationErrorClassificationRequired)
	}
	if scope.State == "NETWORK_CONFLICT" {
		return empty, errors.New(wire.ThreadCollaborationErrorNetworkConflict)
	}
	if scope.State != "CURRENT" {
		return empty, errors.New(wire.ThreadCollaborationErrorWorkerGroupLimit)
	}
	_, authority, _, err := endpointGroupsResolveTx(tx, r, group, at, false)
	if err != nil || authority == nil {
		return empty, errors.New(wire.ThreadCollaborationErrorAuthorizationRequired)
	}
	a := r.anchor.Registration
	return wire.GroupLockHolder{NodeID: a.NodeID, EndpointID: a.EndpointID, PrincipalID: a.PrincipalID, Source: scope.Source}, nil
}
func threadCollaborationPolicyTx(tx *sql.Tx, scope wire.GroupLockScope) (*wire.GroupCoordinationPolicy, error) {
	var raw string
	err := tx.QueryRow(`SELECT policy_json FROM group_coordination_policies_v1 WHERE group_id=? AND network_id=?`, scope.GroupID, scope.NetworkID).Scan(&raw)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var p wire.GroupCoordinationPolicy
	if json.Unmarshal([]byte(raw), &p) != nil || wire.ValidateGroupCoordinationPolicy(p) != nil || p.HubID != scope.HubID || p.NetworkID != scope.NetworkID || p.GroupID != scope.GroupID {
		return nil, ErrNetworkPermission
	}
	return &p, nil
}

// Exactly eight existing rows are inspected under the shared SQLite writer.
// Time comparison uses parsed instants, never lexicographic RFC3339 strings.
func threadCollaborationSlotsTx(tx *sql.Tx, scope wire.GroupLockScope, p wire.GroupCoordinationPolicy, at time.Time) (wire.GroupSlotView, error) {
	v := wire.GroupSlotView{Format: wire.GroupSlotViewFormat, Scope: scope, ObservedAt: appNodeStamp(at), PolicyRevision: p.Revision, PolicyState: p.State, Slots: []wire.GroupLockSlot{}}
	rows, err := tx.Query(`SELECT slot,state,version,generation,holder_json,note,expires_at FROM group_lock_slots_v1 WHERE group_id=? ORDER BY slot`, scope.GroupID)
	if err != nil {
		return v, err
	}
	for rows.Next() {
		var s wire.GroupLockSlot
		var holder string
		if err = rows.Scan(&s.Slot, &s.State, &s.Version, &s.Generation, &holder, &s.Note, &s.ExpiresAt); err != nil {
			break
		}
		if holder != "" {
			var h wire.GroupLockHolder
			if json.Unmarshal([]byte(holder), &h) != nil {
				err = ErrNetworkPermission
				break
			}
			s.Holder = &h
		}
		v.Slots = append(v.Slots, s)
	}
	re := rows.Err()
	rows.Close()
	if err != nil {
		return v, err
	}
	if re != nil {
		return v, re
	}
	if len(v.Slots) != wire.GroupLockSlotCount {
		return v, ErrNetworkPermission
	}
	for i := range v.Slots {
		s := &v.Slots[i]
		if s.State == "HELD" {
			end, e := time.Parse(time.RFC3339Nano, s.ExpiresAt)
			if e != nil {
				return v, e
			}
			if !at.Before(end) {
				if s.Version >= 1<<63-1 {
					return v, errors.New(wire.ThreadCollaborationErrorAtLimit)
				}
				if _, err = tx.Exec(`UPDATE group_lock_slots_v1 SET state='FREE',version=version+1,holder_json='',note='',expires_at='' WHERE group_id=? AND slot=? AND version=? AND generation=? AND state='HELD'`, scope.GroupID, s.Slot, s.Version, s.Generation); err != nil {
					return v, err
				}
				s.State = "FREE"
				s.Version++
				s.Holder = nil
				s.Note = ""
				s.ExpiresAt = ""
			} else {
				s.HolderNameState = "NOT_DISCLOSED"
				// The caller has current exact Group authorization. Only an active
				// holder in that same Group may disclose its existing display name.
				var name string
				disclose := false
				if s.Holder != nil {
					r, e := endpointGroupsRegistrationTx(tx, s.Holder.EndpointID)
					if e == nil && r != nil {
						h, e := threadCollaborationGuardTx(tx, r, scope.GroupID, at)
						disclose = e == nil && h == *s.Holder
					}
				}
				if disclose && tx.QueryRow(`SELECT e.name FROM fabric_endpoints e JOIN endpoint_group_memberships j ON j.endpoint_id=e.id AND j.group_id=? AND j.status='active' WHERE e.id=? AND e.principal_id=? AND e.machine_id=? AND e.status!='left'`, scope.GroupID, s.Holder.EndpointID, s.Holder.PrincipalID, s.Holder.NodeID).Scan(&name) == nil && name != "" && len(name) <= 128 {
					s.HolderName = name
					s.HolderNameState = "VISIBLE"
				}
			}
		}
	}
	return v, wire.ValidateGroupSlotView(v)
}
