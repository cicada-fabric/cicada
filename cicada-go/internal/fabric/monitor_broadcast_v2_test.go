package fabric

import (
	"strings"
	"testing"

	"github.com/cicada-ai/cicada/internal/store"
)

func TestNodeMonitorBroadcastRequiresCurrentBoundCredentials(t *testing.T) {
	service, _, _ := newFabricTestService(t)
	nodeToken, _, err := NewNodeCredential()
	if err != nil {
		t.Fatal(err)
	}
	sessionToken, _, err := NewSessionCredential()
	if err != nil {
		t.Fatal(err)
	}
	previewID := store.NewID("umbprev")
	broadcastID := "bc_" + strings.TrimPrefix(store.NewID("synthetic"), "synthetic_")
	digest := strings.Repeat("0", 64)
	if _, err := service.ListNodeMonitorBroadcastV2Notifications(nodeToken, 16); err == nil {
		t.Fatal("unbound Node listed Monitor notifications")
	}
	if _, err := service.GetNodeMonitorBroadcastV2Notification(nodeToken, previewID); err == nil {
		t.Fatal("unbound Node read Monitor notification metadata")
	}
	if _, err := service.AuthorizeNodeMonitorBroadcastV2Delivery(nodeToken, sessionToken,
		NodeMonitorBroadcastV2AuthorizeInput{PreviewID: previewID, BroadcastID: broadcastID,
			OperationID: "op_" + strings.TrimPrefix(broadcastID, "bc_"), BodyDigest: digest, SnapshotDigest: digest}); err == nil {
		t.Fatal("unbound Node and Session authorized Monitor delivery")
	}
	if _, err := service.RecordNodeMonitorBroadcastV2NotificationReceipt(nodeToken,
		NodeMonitorBroadcastV2ReceiptInput{PreviewID: previewID, BroadcastID: broadcastID,
			SnapshotDigest: digest, BindingID: store.NewID("binding"), BindingEpoch: 1,
			State: store.UserMonitorBroadcastV2NoticeNodeAccepted}); err == nil {
		t.Fatal("unbound Node recorded a Monitor notification receipt")
	}
	if _, err := service.ReportNodeMonitorBroadcastV2RecipientOutcomes(nodeToken, sessionToken,
		NodeMonitorBroadcastV2OutcomeInput{PreviewID: previewID, BroadcastID: broadcastID,
			OperationID: "op_" + strings.TrimPrefix(broadcastID, "bc_"), SnapshotDigest: digest,
			Results: []NodeMonitorBroadcastV2RecipientReport{{Ordinal: 0, EndpointID: "ep_synthetic",
				ChildOperationID: "op_synthetic", MessageID: "msg_synthetic", State: "FAILED",
				FailureCode: "DELIVERY_REJECTED"}}}); err == nil {
		t.Fatal("unbound Node and Session reported Monitor recipient outcomes")
	}
}
