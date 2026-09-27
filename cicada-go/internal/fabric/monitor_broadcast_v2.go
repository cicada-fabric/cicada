package fabric

import "github.com/cicada-ai/cicada/internal/store"

type NodeMonitorBroadcastV2Notification = store.UserMonitorBroadcastV2Notification
type NodeMonitorBroadcastV2Delivery = store.UserMonitorBroadcastV2Delivery
type NodeMonitorBroadcastV2RecipientReport = store.UserMonitorBroadcastV2RecipientReport
type NodeMonitorBroadcastV2RecipientOutcome = store.UserMonitorBroadcastV2RecipientOutcome

// NodeMonitorBroadcastV2AuthorizeInput contains only the fields that the Node
// must echo from its locally verified sealed Client envelope. Node and Session
// credentials travel in their dedicated headers and are hashed before Store.
type NodeMonitorBroadcastV2AuthorizeInput struct {
	PreviewID      string `json:"-"`
	BroadcastID    string `json:"broadcast_id"`
	OperationID    string `json:"operation_id"`
	BodyDigest     string `json:"body_sha256"`
	SnapshotDigest string `json:"snapshot_digest"`
}

// NodeMonitorBroadcastV2ReceiptInput acknowledges durable Node handling of a
// management notification for the exact current Monitor binding and roster.
type NodeMonitorBroadcastV2ReceiptInput struct {
	PreviewID      string `json:"-"`
	BroadcastID    string `json:"broadcast_id"`
	SnapshotDigest string `json:"snapshot_digest"`
	BindingID      string `json:"binding_id"`
	BindingEpoch   uint64 `json:"binding_epoch"`
	State          string `json:"state"`
}

// PreviewID comes from the Node route; neither credential nor route identity
// can be supplied in the untrusted JSON body.
type NodeMonitorBroadcastV2OutcomeInput struct {
	PreviewID      string                                  `json:"-"`
	BroadcastID    string                                  `json:"broadcast_id"`
	OperationID    string                                  `json:"operation_id"`
	SnapshotDigest string                                  `json:"snapshot_digest"`
	Results        []NodeMonitorBroadcastV2RecipientReport `json:"results"`
}

func (s *Service) ListNodeMonitorBroadcastV2Notifications(nodeToken string,
	limit int) ([]NodeMonitorBroadcastV2Notification, error) {
	return s.store.ListUserMonitorBroadcastV2Notifications(HashSessionCredential(nodeToken), limit)
}

func (s *Service) GetNodeMonitorBroadcastV2Notification(nodeToken, previewID string) (
	*NodeMonitorBroadcastV2Notification, error) {
	return s.store.GetUserMonitorBroadcastV2Notification(HashSessionCredential(nodeToken), previewID)
}

func (s *Service) AuthorizeNodeMonitorBroadcastV2Delivery(nodeToken, sessionToken string,
	input NodeMonitorBroadcastV2AuthorizeInput) (*NodeMonitorBroadcastV2Delivery, error) {
	return s.store.AuthorizeUserMonitorBroadcastV2Delivery(store.AuthorizeUserMonitorBroadcastV2Input{
		NodeCredentialDigest:    HashSessionCredential(nodeToken),
		SessionCredentialDigest: HashSessionCredential(sessionToken),
		PreviewID:               input.PreviewID,
		BroadcastID:             input.BroadcastID,
		OperationID:             input.OperationID,
		BodyDigest:              input.BodyDigest,
		SnapshotDigest:          input.SnapshotDigest,
	})
}

// PreviewNodeMonitorBroadcastV2Delivery reads the exact approved evidence for
// the current Node and Monitor Session without reserving dispatch.
func (s *Service) PreviewNodeMonitorBroadcastV2Delivery(nodeToken, sessionToken,
	previewID string) (*NodeMonitorBroadcastV2Delivery, error) {
	return s.store.PreviewUserMonitorBroadcastV2Delivery(store.PreviewUserMonitorBroadcastV2Input{
		NodeCredentialDigest:    HashSessionCredential(nodeToken),
		SessionCredentialDigest: HashSessionCredential(sessionToken),
		PreviewID:               previewID,
	})
}

func (s *Service) RecordNodeMonitorBroadcastV2NotificationReceipt(nodeToken string,
	input NodeMonitorBroadcastV2ReceiptInput) (*NodeMonitorBroadcastV2Notification, error) {
	return s.store.RecordUserMonitorBroadcastV2NotificationReceipt(
		store.UserMonitorBroadcastV2NotificationReceiptInput{
			NodeCredentialDigest: HashSessionCredential(nodeToken),
			PreviewID:            input.PreviewID,
			BroadcastID:          input.BroadcastID,
			SnapshotDigest:       input.SnapshotDigest,
			BindingID:            input.BindingID,
			BindingEpoch:         input.BindingEpoch,
			State:                input.State,
		})
}

func (s *Service) ReportNodeMonitorBroadcastV2RecipientOutcomes(nodeToken, sessionToken string,
	input NodeMonitorBroadcastV2OutcomeInput) ([]NodeMonitorBroadcastV2RecipientOutcome, error) {
	return s.store.ReportUserMonitorBroadcastV2RecipientOutcomes(store.UserMonitorBroadcastV2OutcomeReportInput{
		NodeCredentialDigest:    HashSessionCredential(nodeToken),
		SessionCredentialDigest: HashSessionCredential(sessionToken),
		PreviewID:               input.PreviewID,
		BroadcastID:             input.BroadcastID,
		OperationID:             input.OperationID,
		SnapshotDigest:          input.SnapshotDigest,
		Results:                 input.Results,
	})
}
