package store

import (
	"encoding/json"
	"time"
)

const CrossOwnerAdmissionPreviewOperation = "space.foreign_endpoint_preview"

// CrossOwnerGroupPreconsentPreview is the exact, read-only review shown to an
// Endpoint Owner before authorizing that Endpoint to join a foreign Group.
// It intentionally omits Node IDs, native session IDs, workspaces, key
// candidates and other Group members.
type CrossOwnerGroupPreconsentPreview struct {
	HubID                   string   `json:"hub_id"`
	NetworkID               string   `json:"network_id"`
	NetworkName             string   `json:"network_name"`
	GroupID                 string   `json:"group_id"`
	GroupName               string   `json:"group_name"`
	GroupOwnerID            string   `json:"group_owner_id"`
	GroupOwnerName          string   `json:"group_owner_name"`
	EndpointID              string   `json:"endpoint_id"`
	EndpointName            string   `json:"endpoint_name"`
	PrincipalID             string   `json:"principal_id"`
	EndpointOwnerID         string   `json:"endpoint_owner_id"`
	EndpointOwnerName       string   `json:"endpoint_owner_name"`
	AdmissionID             string   `json:"admission_id"`
	AdmissionState          string   `json:"admission_state"`
	Grants                  []string `json:"grants"`
	ExpiresAt               string   `json:"expires_at"`
	GroupRevision           int64    `json:"group_revision"`
	MembershipID            string   `json:"membership_id"`
	MembershipRevision      int64    `json:"membership_revision"`
	BindingID               string   `json:"binding_id"`
	BindingEpoch            uint64   `json:"binding_epoch"`
	ContextPolicy           string   `json:"context_policy"`
	CrossOwnerContextShared bool     `json:"cross_owner_context_shared"`
	HistoryIncluded         bool     `json:"history_included"`
}

// PreviewCrossOwnerGroupPreconsentForClientRequest reads one exact active
// admission for its foreign Endpoint Owner. It runs only from a trusted,
// accepted encrypted Client request routed to CrossOwnerAdmissionPreviewOperation.
func (s *Store) PreviewCrossOwnerGroupPreconsentForClientRequest(requestID, ownerID,
	admissionID string) (*CrossOwnerGroupPreconsentPreview, error) {
	if admissionID == "" {
		return nil, ErrCrossOwnerGroupDenied
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	tx, err := s.db.Begin()
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()
	actor, err := crossOwnerClientRequestTx(tx, requestID, ownerID, CrossOwnerAdmissionPreviewOperation)
	if err != nil {
		return nil, err
	}
	requestTime := time.Now().UTC()
	a, err := scanCrossOwnerAdmission(tx.QueryRow(`SELECT `+crossOwnerAdmissionColumns+
		` FROM cross_owner_group_admissions_v2 WHERE id=?`, admissionID))
	if err != nil || a.EndpointOwnerID != ownerID || a.HubID != actor.HubID ||
		crossOwnerAdmissionCurrentTx(tx, a, requestTime) != nil {
		return nil, ErrCrossOwnerGroupDenied
	}
	var preview CrossOwnerGroupPreconsentPreview
	var groupState, contextPolicy, networkState, endpointPrincipalKind string
	var endpointState, bindingStatus, bindingExpiry, boundNodeID, grantsJSON string
	err = tx.QueryRow(`SELECT a.hub_id,a.network_id,n.name,a.group_id,g.name,a.group_owner_id,
COALESCE(NULLIF(group_owner.display_name,''),group_owner.name),a.endpoint_id,e.name,
a.principal_id,a.endpoint_owner_id,COALESCE(NULLIF(endpoint_owner.display_name,''),endpoint_owner.name),
a.id,a.state,a.grants_json,a.expires_at,a.group_revision,a.membership_id,a.membership_revision,
e.binding_id,b.epoch,b.status,b.lease_expires_at,e.machine_id,g.context_policy,g.state,n.state,e.status,
endpoint_principal.kind
FROM cross_owner_group_admissions_v2 a
JOIN groups g ON g.id=a.group_id
JOIN principals group_owner ON group_owner.id=g.owner_principal_id
 AND group_owner.owner_id=a.group_owner_id AND group_owner.kind='human' AND group_owner.status='active'
JOIN networks_v2 n ON n.id=a.network_id AND n.hub_id=a.hub_id
JOIN fabric_endpoints e ON e.id=a.endpoint_id AND e.principal_id=a.principal_id
 AND e.owner=a.endpoint_owner_id AND e.migration_state='READY'
JOIN principals endpoint_principal ON endpoint_principal.id=e.principal_id
 AND endpoint_principal.kind='agent' AND endpoint_principal.status='active'
JOIN principals endpoint_owner ON endpoint_owner.id=a.endpoint_owner_id
 AND endpoint_owner.owner_id=e.owner AND endpoint_owner.kind='human' AND endpoint_owner.status='active'
JOIN session_bindings b ON b.id=e.binding_id AND b.endpoint_id=e.id AND b.principal_id=e.principal_id
 AND b.node_id=e.machine_id
WHERE a.id=?`, admissionID).Scan(
		&preview.HubID, &preview.NetworkID, &preview.NetworkName, &preview.GroupID, &preview.GroupName,
		&preview.GroupOwnerID, &preview.GroupOwnerName, &preview.EndpointID, &preview.EndpointName,
		&preview.PrincipalID, &preview.EndpointOwnerID, &preview.EndpointOwnerName,
		&preview.AdmissionID, &preview.AdmissionState, &grantsJSON, &preview.ExpiresAt,
		&preview.GroupRevision, &preview.MembershipID, &preview.MembershipRevision,
		&preview.BindingID, &preview.BindingEpoch, &bindingStatus, &bindingExpiry, &boundNodeID,
		&contextPolicy, &groupState, &networkState, &endpointState, &endpointPrincipalKind)
	if err != nil || preview.AdmissionID != admissionID || preview.EndpointOwnerID != ownerID ||
		preview.GroupOwnerID == ownerID || preview.GroupOwnerID == "" || preview.NetworkID == "" ||
		preview.GroupID == "" || preview.EndpointID == "" || preview.BindingID == "" ||
		preview.BindingEpoch == 0 || !isActiveBindingStatus(bindingStatus) || boundNodeID == "" ||
		!networkExpiryAllows(bindingExpiry, requestTime) || endpointPrincipalKind != PrincipalKindAgent ||
		!configuredGroupContextPolicy(contextPolicy) || groupState != GroupStateActive || networkState != NetworkStateActive ||
		endpointState == "left" || requireCurrentOwnerBoundGroupNodeTx(tx, boundNodeID, ownerID, actor.HubID) != nil {
		return nil, ErrCrossOwnerGroupDenied
	}
	if json.Unmarshal([]byte(grantsJSON), &preview.Grants) != nil {
		return nil, ErrCrossOwnerGroupDenied
	}
	preview.Grants, err = normalizeCrossOwnerGrants(preview.Grants)
	if err != nil {
		return nil, ErrCrossOwnerGroupDenied
	}
	preview.ContextPolicy = contextPolicy
	preview.CrossOwnerContextShared = true
	preview.HistoryIncluded = false
	if err := tx.Commit(); err != nil {
		return nil, err
	}
	return &preview, nil
}
