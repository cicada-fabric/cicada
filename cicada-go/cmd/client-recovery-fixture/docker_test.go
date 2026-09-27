package main

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"os"
	"testing"
	"time"

	"github.com/cicada-ai/cicada/internal/clientwire"
	"github.com/cicada-ai/cicada/internal/e2ee"
	"github.com/cicada-ai/cicada/internal/store"
)

// TestClientDockerHubRecoveryFixture runs against the separate, fixed Hub
// runtime image. The test runner has only a disposable bind-mounted database;
// Android and production state are outside this test.
func TestClientDockerHubRecoveryFixture(t *testing.T) {
	baseURL, dbPath := os.Getenv("CICADA_TEST_HUB_URL"), os.Getenv("CICADA_TEST_HUB_DB")
	if baseURL == "" || dbPath == "" {
		t.Skip("requires an isolated Docker Hub and disposable database")
	}
	if err := requireDisposableDatabase(dbPath); err != nil {
		t.Fatal(err)
	}
	client := &http.Client{Timeout: 10 * time.Second}
	call := func(path string, body []byte) (int, []byte) {
		t.Helper()
		method := http.MethodPost
		if body == nil {
			method = http.MethodGet
		}
		request, err := http.NewRequest(method, baseURL+path, bytes.NewReader(body))
		if err != nil {
			t.Fatal(err)
		}
		response, err := client.Do(request)
		if err != nil {
			t.Fatal(err)
		}
		defer response.Body.Close()
		data, err := io.ReadAll(io.LimitReader(response.Body, 256*1024+1))
		if err != nil || len(data) > 256*1024 {
			t.Fatal("invalid Hub response size")
		}
		return response.StatusCode, data
	}
	var hub struct {
		HubID                 string              `json:"hub_id"`
		ControlPublicIdentity e2ee.PublicIdentity `json:"control_public_identity"`
	}
	status, identity := call("/v2/client/identity", nil)
	if status != http.StatusOK || json.Unmarshal(identity, &hub) != nil || hub.HubID == "" {
		t.Fatal("fixed Hub identity unavailable")
	}
	db, err := store.New(dbPath)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	localHubID, err := db.GetClientHubID()
	if err != nil || localHubID != hub.HubID {
		t.Fatal("test database is not the fixed Hub database")
	}
	const ownerID = "docker-recovery-owner"
	if err := db.EnsureLocalOwnerPrincipal(ownerID); err != nil {
		t.Fatal(err)
	}
	owner, err := e2ee.NewIdentity()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := db.RegisterOwnerApprovalKeyLocal(ownerID, owner.Public()); err != nil {
		t.Fatal(err)
	}
	for _, scenario := range []struct {
		mode, code string
		status     int
	}{
		{"processing", "STILL_PROCESSING", http.StatusConflict},
		{"uncertain", "OUTCOME_UNCERTAIN", http.StatusOK},
		{"legacy", "RECOVERY_UNAVAILABLE", http.StatusConflict},
	} {
		t.Run(scenario.mode, func(t *testing.T) {
			device, err := e2ee.NewIdentity()
			if err != nil {
				t.Fatal(err)
			}
			deviceID := "docker-" + scenario.mode
			grant, err := owner.SignOwnerDeviceGrant(ownerID, deviceID, device.Public(), hub.HubID,
				e2ee.OwnerDevicePurposeControl, time.Now().Add(-time.Minute), time.Now().Add(time.Hour))
			if err != nil {
				t.Fatal(err)
			}
			if _, err := db.RegisterClientDeviceFromOwnerGrant(store.RegisterClientDeviceInput{
				OwnerID: ownerID, OwnerKeyID: owner.Public().ID, DeviceID: deviceID,
				DevicePublic: device.Public(), OwnerDeviceGrant: grant,
			}); err != nil {
				t.Fatal(err)
			}
			binding := clientwire.Binding{HubID: hub.HubID, OwnerID: ownerID,
				DeviceID: deviceID, SessionEpoch: 1, HubKeyVersion: 1, DeviceKeyVersion: 1}
			route := clientwire.Route{Version: clientwire.Version,
				Direction: clientwire.DirectionRequest, HubID: hub.HubID,
				OwnerID: ownerID, DeviceID: deviceID, SessionEpoch: 1, Sequence: 1,
				OperationID: "docker-recovery-" + scenario.mode, Operation: "status.snapshot",
				SenderKeyID: device.Public().ID, SenderKeyVersion: 1,
				ReceiverKeyID: hub.ControlPublicIdentity.ID, ReceiverKeyVersion: 1}
			packet, err := clientwire.SealRequest(device, hub.ControlPublicIdentity,
				binding, route, []byte(`{}`))
			if err != nil {
				t.Fatal(err)
			}
			if err := run([]string{"--db", dbPath, "--mode", scenario.mode}, bytes.NewReader(packet)); err != nil {
				t.Fatal(err)
			}
			if scenario.mode == "uncertain" {
				// The in-process restart test covers the crash itself. Here we
				// verify the fixed image's wire behavior for the durable state
				// that startup recovery produces after that crash.
				if _, err := db.UpdateClientRequestStatus(ownerID, deviceID,
					route.OperationID, store.ClientRequestUncertain); err != nil {
					t.Fatal(err)
				}
			}
			status, response := call("/v2/client/rpc/recover", packet)
			if status != scenario.status {
				t.Fatalf("fixed Hub recovery status=%d want=%d", status, scenario.status)
			}
			if status == http.StatusConflict {
				var failure struct {
					Code string `json:"code"`
				}
				if err := json.Unmarshal(response, &failure); err != nil || failure.Code != scenario.code {
					t.Fatalf("fixed Hub recovery code=%q error=%v", failure.Code, err)
				}
			} else {
				opened, err := clientwire.OpenResponse(device, hub.ControlPublicIdentity,
					binding, response)
				if err != nil || opened.Route.Sequence != 1 || opened.Route.OperationID != route.OperationID {
					t.Fatalf("fixed Hub uncertainty packet invalid: %v", err)
				}
				var notice struct {
					ErrorCode string `json:"error_code"`
				}
				if err := json.Unmarshal(opened.Plaintext, &notice); err != nil || notice.ErrorCode != scenario.code {
					t.Fatalf("fixed Hub uncertainty code=%q error=%v", notice.ErrorCode, err)
				}
			}
			status, _ = call("/v2/client/rpc", packet)
			if status != http.StatusConflict {
				t.Fatalf("fixed Hub reran interrupted request: status=%d", status)
			}
		})
	}
}
