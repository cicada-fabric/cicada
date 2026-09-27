package control

import (
	"encoding/json"
	"errors"

	"github.com/cicada-ai/cicada/internal/store"
)

const clientMonitorBroadcastResultMaxBytes = 56 * 1024

// ClientMonitorBroadcastResult is the owner-facing projection of a Monitor
// approval record. It intentionally excludes owner/device/session internals,
// the full recipient snapshot, native session IDs, local paths and sealed
// payload bytes. The consent preview is the bounded public evidence a Client
// needs to verify before asking the owner to sign the v2 envelope.
type ClientMonitorBroadcastResult struct {
	PreviewID            string                               `json:"preview_id"`
	BroadcastID          string                               `json:"broadcast_id"`
	Status               string                               `json:"status"`
	GroupID              string                               `json:"group_id"`
	MonitorEndpointID    string                               `json:"monitor_endpoint_id"`
	BodySHA256           string                               `json:"body_sha256"`
	SnapshotDigest       string                               `json:"snapshot_digest"`
	ExpiresAt            string                               `json:"expires_at"`
	ApprovedAt           string                               `json:"approved_at,omitempty"`
	DispatchAuthorizedAt string                               `json:"dispatch_authorized_at,omitempty"`
	SealedPayloadDigest  string                               `json:"sealed_payload_digest,omitempty"`
	Preview              *store.UserMonitorBroadcastV2Preview `json:"preview,omitempty"`
}

func clientMonitorBroadcastResult(record *store.UserMonitorBroadcastV2, includePreview bool) (*ClientMonitorBroadcastResult, error) {
	if record == nil || record.PreviewID == "" || record.BroadcastID == "" ||
		record.GroupID == "" || record.MonitorEndpointID == "" || record.SnapshotDigest == "" {
		return nil, errors.New("Monitor approval result is unavailable")
	}
	result := &ClientMonitorBroadcastResult{
		PreviewID: record.PreviewID, BroadcastID: record.BroadcastID, Status: record.Status,
		GroupID: record.GroupID, MonitorEndpointID: record.MonitorEndpointID,
		BodySHA256: record.BodyDigest, SnapshotDigest: record.SnapshotDigest,
		ExpiresAt: record.ExpiresAt, ApprovedAt: record.ApprovedAt,
		DispatchAuthorizedAt: record.DispatchAuthorizedAt,
		SealedPayloadDigest:  record.SealedPayloadDigest,
	}
	if includePreview {
		result.Preview = record.Preview
	}
	encoded, err := json.Marshal(result)
	if err != nil || len(encoded) > clientMonitorBroadcastResultMaxBytes {
		return nil, errors.New("Monitor approval result exceeds the Client response limit")
	}
	return result, nil
}

// ClientPrepareMonitorBroadcast binds a new approval preview to the accepted
// encrypted request ID supplied by the RPC dispatcher. Group and Monitor IDs
// are selectors; Store derives the authenticated owner and current Guard from
// that accepted request and current topology.
func (c *Control) ClientPrepareMonitorBroadcast(ownerID, clientRequestID, groupID,
	monitorEndpointID, bodySHA256 string) (*ClientMonitorBroadcastResult, error) {
	if c == nil || c.store == nil {
		return nil, errors.New("Monitor broadcast approval service is unavailable")
	}
	if err := c.ValidateClientSessionOwner(ownerID); err != nil {
		return nil, err
	}
	record, err := c.store.PrepareUserMonitorBroadcastV2(store.PrepareUserMonitorBroadcastV2Input{
		ClientRequestID: clientRequestID, GroupID: groupID,
		MonitorEndpointID: monitorEndpointID, BodyDigest: bodySHA256,
	})
	if err != nil {
		return nil, err
	}
	return clientMonitorBroadcastResult(record, true)
}

// ClientConfirmMonitorBroadcast accepts only an approval created with the
// consent-bound preview now required by the public Client surface. Historical
// internal v1 rows remain readable by their legacy implementation.
func (c *Control) ClientConfirmMonitorBroadcast(ownerID, clientRequestID,
	previewID, snapshotDigest, bodySHA256 string, sealedPayload []byte) (*ClientMonitorBroadcastResult, error) {
	if c == nil || c.store == nil {
		return nil, errors.New("Monitor broadcast approval service is unavailable")
	}
	if err := c.ValidateClientSessionOwner(ownerID); err != nil {
		return nil, err
	}
	current, err := c.store.GetUserMonitorBroadcastV2Status(clientRequestID, previewID)
	if err != nil || current.Preview == nil {
		return nil, errors.New("consent-bound Monitor preview is unavailable")
	}
	record, err := c.store.ConfirmUserMonitorBroadcastV2(store.ConfirmUserMonitorBroadcastV2Input{
		ClientRequestID: clientRequestID, PreviewID: previewID,
		SnapshotDigest: snapshotDigest, BodyDigest: bodySHA256,
		SealedPayload: sealedPayload,
	})
	if err != nil {
		return nil, err
	}
	// Confirm commits the consent-bound approval before waking the Monitor Node.
	// This body-free hint only reduces latency; the Node must still claim under
	// its current credential, binding and Guard. Periodic reconciliation covers
	// a missed or coalesced hint.
	if current.Snapshot != nil && current.Snapshot.Source.NodeID != "" {
		c.Fabric().NotifyNodeClaimHint(current.Snapshot.Source.NodeID)
	}
	return clientMonitorBroadcastResult(record, false)
}

// ClientMonitorBroadcastStatus returns approval state and the existing bounded
// per-recipient evidence ledger. The authenticated accepted request ID is
// checked against the exact current device/epoch/key in Store.
func (c *Control) ClientMonitorBroadcastStatus(ownerID, clientRequestID,
	previewID string) (*store.UserMonitorBroadcastV2OutcomeStatus, error) {
	if c == nil || c.store == nil {
		return nil, errors.New("Monitor broadcast status service is unavailable")
	}
	if err := c.ValidateClientSessionOwner(ownerID); err != nil {
		return nil, err
	}
	current, err := c.store.GetUserMonitorBroadcastV2Status(clientRequestID, previewID)
	if err != nil || current.Preview == nil {
		return nil, errors.New("consent-bound Monitor preview is unavailable")
	}
	return c.store.GetUserMonitorBroadcastV2OutcomeStatus(clientRequestID, previewID)
}

// ClientRecoverMonitorBroadcast performs a read-only lookup using the original
// prepare operation ID. Store binds it to the current accepted owner/device/
// epoch/key request; this path cannot create or repeat a mutation.
func (c *Control) ClientRecoverMonitorBroadcast(ownerID, clientRequestID,
	prepareOperationID string) (*ClientMonitorBroadcastResult, error) {
	if c == nil || c.store == nil {
		return nil, errors.New("Monitor broadcast recovery service is unavailable")
	}
	if err := c.ValidateClientSessionOwner(ownerID); err != nil {
		return nil, err
	}
	record, err := c.store.RecoverUserMonitorBroadcastV2(clientRequestID, prepareOperationID)
	if err != nil {
		return nil, err
	}
	return clientMonitorBroadcastResult(record, true)
}
