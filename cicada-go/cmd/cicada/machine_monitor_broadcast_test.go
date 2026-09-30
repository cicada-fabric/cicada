package main

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/cicada-ai/cicada/internal/nodeinbox"
	"github.com/cicada-ai/cicada/internal/store"
)

func monitorBroadcastTestBridge(base *machineAgentJoinBridge, baseURL string) *machineAgentJoinBridge {
	return &machineAgentJoinBridge{baseURL: baseURL, stateDir: base.stateDir,
		nodeID: base.nodeID, nodeToken: base.nodeToken, ctx: context.Background()}
}

func relayRecordedMonitorResponse(response http.ResponseWriter, recorded *httptest.ResponseRecorder, body []byte) {
	for name, values := range recorded.Header() {
		for _, value := range values {
			response.Header().Add(name, value)
		}
	}
	response.WriteHeader(recorded.Code)
	_, _ = response.Write(body)
}

func TestMachineMonitorNotificationEmptyListDoesNotCreateInbox(t *testing.T) {
	f := newMonitorBroadcastIntegrationFixture(t)
	if _, err := f.local.store.RevokeClientDevice(f.preview.OwnerID, f.deviceID, f.clientVersion); err != nil {
		t.Fatalf("revoke synthetic Client to make its stale notice disappear: %v", err)
	}

	inboxPath := filepath.Join(t.TempDir(), "node-state", "monitor-broadcast-inbox.sqlite")
	var inbox *nodeinbox.Inbox
	if err := processPinnedTestMachineMonitorBroadcastNotifications(context.Background(), f.local.bridge, &inbox, inboxPath); err != nil {
		t.Fatalf("process valid empty Monitor notice list: %v", err)
	}
	if inbox != nil {
		_ = inbox.Close()
		t.Fatal("valid empty Monitor notice list opened an inbox")
	}
	if _, err := os.Stat(inboxPath); !os.IsNotExist(err) {
		t.Fatalf("valid empty Monitor notice list created an inbox path: stat err=%v", err)
	}
}

func TestMachineMonitorNotificationRejectsNestedHubHintBeforeInboxOpen(t *testing.T) {
	f := newMonitorBroadcastIntegrationFixture(t)
	listPath := "/v2/relay/nodes/" + f.local.nodeID + "/monitor/broadcasts"
	proxy := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		recorded := httptest.NewRecorder()
		f.hub.Config.Handler.ServeHTTP(recorded, request)
		body := append([]byte(nil), recorded.Body.Bytes()...)
		if request.Method == http.MethodGet && request.URL.Path == listPath && recorded.Code == http.StatusOK {
			var listing struct {
				HubID         string           `json:"hub_id"`
				Notifications []map[string]any `json:"notifications"`
			}
			if err := json.Unmarshal(body, &listing); err != nil || len(listing.Notifications) != 1 {
				t.Errorf("real Hub did not return the expected synthetic notice: %s (%v)", body, err)
			} else {
				listing.Notifications[0]["hub_id"] = "hub_other_synthetic"
				body, _ = json.Marshal(listing)
			}
		}
		relayRecordedMonitorResponse(response, recorded, body)
	}))
	t.Cleanup(proxy.Close)

	inboxPath := filepath.Join(t.TempDir(), "node-state", "monitor-broadcast-inbox.sqlite")
	var inbox *nodeinbox.Inbox
	bridge := monitorBroadcastTestBridge(f.local.bridge, proxy.URL)
	err := processPinnedTestMachineMonitorBroadcastNotifications(context.Background(), bridge, &inbox, inboxPath)
	if err == nil || !strings.Contains(err.Error(), "invalid Node or Hub hint") {
		t.Fatalf("malformed nested Hub hint was not rejected: %v", err)
	}
	if inbox != nil {
		_ = inbox.Close()
		t.Fatal("malformed nested Hub hint opened the inbox")
	}
	if _, err := os.Stat(inboxPath); !os.IsNotExist(err) {
		t.Fatalf("malformed nested Hub hint created an inbox path: stat err=%v", err)
	}
}

func TestMachineMonitorNotificationRechecksClientGuardBeforeInjection(t *testing.T) {
	f := newMonitorBroadcastIntegrationFixture(t)
	_, fakeCountPath := installMachineSealedFakeCodex(t, false, f.local.nodeToken)
	listPath := "/v2/relay/nodes/" + f.local.nodeID + "/monitor/broadcasts"
	detailPath := listPath + "/" + f.preview.PreviewID
	var stateMu sync.Mutex
	var receiptRevoked, detailRejected bool
	proxy := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		recorded := httptest.NewRecorder()
		f.hub.Config.Handler.ServeHTTP(recorded, request)
		body := append([]byte(nil), recorded.Body.Bytes()...)
		if request.Method == http.MethodPost && strings.HasSuffix(request.URL.Path, "/receipt") && recorded.Code == http.StatusOK {
			var receipt struct {
				Notification *struct {
					ReceiptState string `json:"receipt_state"`
				} `json:"notification"`
			}
			if err := json.Unmarshal(body, &receipt); err != nil {
				t.Errorf("decode real Hub receipt response: %v", err)
			} else if receipt.Notification != nil && receipt.Notification.ReceiptState == "NODE_ACCEPTED" {
				if _, err := f.local.store.RevokeClientDevice(f.preview.OwnerID, f.deviceID, f.clientVersion); err != nil {
					t.Errorf("revoke synthetic Client after NODE_ACCEPTED: %v", err)
				} else {
					stateMu.Lock()
					receiptRevoked = true
					stateMu.Unlock()
				}
			}
		}
		if request.Method == http.MethodGet && request.URL.Path == detailPath {
			stateMu.Lock()
			detailRejected = recorded.Code == http.StatusNotFound
			stateMu.Unlock()
		}
		relayRecordedMonitorResponse(response, recorded, body)
	}))
	t.Cleanup(proxy.Close)

	inboxPath := machineMonitorBroadcastInboxPath(f.local.stateDir, f.local.nodeID)
	var inbox *nodeinbox.Inbox
	bridge := monitorBroadcastTestBridge(f.local.bridge, proxy.URL)
	if err := processPinnedTestMachineMonitorBroadcastNotifications(context.Background(), bridge, &inbox, inboxPath); err != nil {
		t.Fatalf("process revoked Monitor notice: %v", err)
	}
	if inbox == nil {
		t.Fatal("non-empty Monitor notice list did not open the durable inbox")
	}
	defer inbox.Close()
	stateMu.Lock()
	gotReceiptRevoked, gotDetailRejected := receiptRevoked, detailRejected
	stateMu.Unlock()
	if !gotReceiptRevoked || !gotDetailRejected {
		t.Fatalf("revocation/fresh detail sequence missing: receiptRevoked=%v detailRejected=%v",
			gotReceiptRevoked, gotDetailRejected)
	}
	if _, err := os.Stat(fakeCountPath); !os.IsNotExist(err) {
		contents, _ := os.ReadFile(fakeCountPath)
		t.Fatalf("native fake queue ran after the fresh detail Guard rejected the Client: count=%q err=%v", contents, err)
	}
	delivery, err := inbox.Get(context.Background(), f.preview.PreviewID)
	if err != nil || delivery.State != nodeinbox.FAILED {
		t.Fatalf("revoked notice was not rejected before injection: delivery=%+v err=%v", delivery, err)
	}
}

func TestMachineMonitorBroadcastInboxOnlyOpensExistingRegularFiles(t *testing.T) {
	dir := t.TempDir()
	absentPath := filepath.Join(dir, "absent", "monitor-broadcast-inbox.sqlite")
	inbox, err := openExistingMachineMonitorBroadcastInbox(absentPath)
	if err != nil || inbox != nil {
		t.Fatalf("absent Monitor inbox did not remain unopened: inbox=%v err=%v", inbox, err)
	}
	if _, err := os.Stat(absentPath); !os.IsNotExist(err) {
		t.Fatalf("absent Monitor inbox helper created the path: stat err=%v", err)
	}

	target := filepath.Join(dir, "regular-file")
	if err := os.WriteFile(target, []byte("synthetic target"), 0o600); err != nil {
		t.Fatal(err)
	}
	symlinkPath := filepath.Join(dir, "monitor-broadcast-inbox.sqlite")
	if err := os.Symlink(target, symlinkPath); err != nil {
		t.Fatal(err)
	}
	inbox, err = openExistingMachineMonitorBroadcastInbox(symlinkPath)
	if inbox != nil {
		_ = inbox.Close()
		t.Fatal("Monitor inbox helper followed a symlink")
	}
	if err == nil || !strings.Contains(err.Error(), "not a regular file") {
		t.Fatalf("Monitor inbox symlink was not rejected as non-regular: %v", err)
	}
}

func TestMachineMonitorExpiredNoticeReceiptRemainsCorrelatedWithoutAuthorization(t *testing.T) {
	notice := store.UserMonitorBroadcastV2Notification{
		HubID: "hub_monitor_ack_synthetic", PreviewID: "umbprev_expired_ack_test",
		BroadcastID: "bc_0123456789abcdef0123456789abcdef", GroupID: "group_monitor_ack_synthetic",
		MonitorEndpointID: "endpoint_monitor_ack_synthetic", NodeID: "node_monitor_ack_synthetic",
		NativeSessionID: "native-session-monitor-ack", BindingID: "binding_monitor_ack_synthetic",
		BindingEpoch: 7, BodyDigest: strings.Repeat("a", 64), SnapshotDigest: strings.Repeat("b", 64),
		ExpiresAt:    time.Now().UTC().Add(-time.Minute).Format(time.RFC3339Nano),
		ReceiptState: store.UserMonitorBroadcastV2NoticePending,
	}
	t.Setenv("CICADA_HUB_ID", notice.HubID)

	var pathsMu sync.Mutex
	var paths []string
	var receiptMatched bool
	server := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		pathsMu.Lock()
		paths = append(paths, request.Method+" "+request.URL.Path)
		pathsMu.Unlock()
		if request.Header.Get("Authorization") != "CicadaNode synthetic-node-token" {
			t.Errorf("Monitor receipt/detail used unexpected Node authorization: %q", request.Header.Get("Authorization"))
		}
		basePath := "/v2/relay/nodes/" + notice.NodeID + "/monitor/broadcasts/" + notice.PreviewID
		if request.Method == http.MethodPost && request.URL.Path == basePath+"/receipt" {
			var input struct {
				BroadcastID    string `json:"broadcast_id"`
				SnapshotDigest string `json:"snapshot_digest"`
				BindingID      string `json:"binding_id"`
				BindingEpoch   uint64 `json:"binding_epoch"`
				State          string `json:"state"`
			}
			if err := json.NewDecoder(request.Body).Decode(&input); err != nil {
				t.Errorf("decode historical receipt request: %v", err)
			} else {
				receiptMatched = input.BroadcastID == notice.BroadcastID &&
					input.SnapshotDigest == notice.SnapshotDigest && input.BindingID == notice.BindingID &&
					input.BindingEpoch == notice.BindingEpoch && input.State == "NODE_ACCEPTED"
				if !receiptMatched {
					t.Errorf("historical receipt did not match immutable notice metadata: %+v", input)
				}
			}
			reply := notice
			reply.ReceiptState = store.UserMonitorBroadcastV2NoticeNodeAccepted
			response.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(response).Encode(monitorBroadcastNotificationResponse{
				HubID: notice.HubID, Notification: &reply,
			})
			return
		}
		if request.Method == http.MethodGet && request.URL.Path == basePath {
			reply := notice
			reply.ReceiptState = store.UserMonitorBroadcastV2NoticeNodeAccepted
			response.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(response).Encode(monitorBroadcastNotificationResponse{
				HubID: notice.HubID, Notification: &reply,
			})
			return
		}
		http.NotFound(response, request)
	}))
	t.Cleanup(server.Close)
	bridge := &machineAgentJoinBridge{baseURL: server.URL, nodeID: notice.NodeID,
		nodeToken: "synthetic-node-token", ctx: context.Background()}

	if err := bridge.reportMonitorNotification(notice, nodeinbox.NODE_RECEIVED); err != nil {
		t.Fatalf("correlated factual receipt was rejected after approval expiry: %v", err)
	}
	if _, err := bridge.monitorBroadcastNotification(notice.PreviewID); err == nil {
		t.Fatal("fresh delivery detail remained available after approval expiry")
	}
	pathsMu.Lock()
	gotPaths := append([]string(nil), paths...)
	pathsMu.Unlock()
	if !receiptMatched || len(gotPaths) != 2 ||
		gotPaths[0] != "POST /v2/relay/nodes/"+notice.NodeID+"/monitor/broadcasts/"+notice.PreviewID+"/receipt" ||
		gotPaths[1] != "GET /v2/relay/nodes/"+notice.NodeID+"/monitor/broadcasts/"+notice.PreviewID {
		t.Fatalf("receipt or fresh detail used an unexpected route: matched=%v paths=%v", receiptMatched, gotPaths)
	}
}
