package main

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/cicada-ai/cicada/internal/clientwire"
	"github.com/cicada-ai/cicada/internal/control"
	"github.com/cicada-ai/cicada/internal/e2ee"
	"github.com/cicada-ai/cicada/internal/server"
	"github.com/cicada-ai/cicada/internal/store"
)

func TestRecoveryFixtureRequiresDisposableMarker(t *testing.T) {
	path := filepath.Join(t.TempDir(), "cicada.sqlite3")
	if err := os.WriteFile(path, nil, 0600); err != nil {
		t.Fatal(err)
	}
	if err := requireDisposableDatabase(path); err == nil {
		t.Fatal("unmarked database was accepted")
	}
	if err := os.WriteFile(filepath.Join(filepath.Dir(path), disposableMarker), []byte("disposable\n"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := requireDisposableDatabase(path); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(filepath.Dir(path), "linked.sqlite3")
	if err := os.Symlink(path, link); err != nil {
		t.Fatal(err)
	}
	if err := requireDisposableDatabase(link); err == nil {
		t.Fatal("symlink database was accepted")
	}
}

func TestRecoveryFixtureAgainstRealHTTPHandler(t *testing.T) {
	for _, scenario := range []struct {
		mode, code string
		status     int
	}{
		{"processing", "STILL_PROCESSING", http.StatusConflict},
		{"uncertain", "OUTCOME_UNCERTAIN", http.StatusOK},
		{"legacy", "RECOVERY_UNAVAILABLE", http.StatusConflict},
	} {
		t.Run(scenario.mode, func(t *testing.T) {
			root := t.TempDir()
			state := filepath.Join(root, "state")
			manager, err := control.New(control.Config{StateDir: state,
				WorkspaceRoot: filepath.Join(root, "workspace")})
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() {
				ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
				defer cancel()
				_ = manager.Shutdown(ctx)
			})
			dbPath := filepath.Join(state, "cicada.sqlite3")
			if err := os.WriteFile(filepath.Join(state, disposableMarker), []byte("disposable\n"), 0600); err != nil {
				t.Fatal(err)
			}
			db, err := store.New(dbPath)
			if err != nil {
				t.Fatal(err)
			}
			ownerID := manager.Identity().ID
			owner, err := e2ee.NewIdentity()
			if err != nil {
				t.Fatal(err)
			}
			device, err := e2ee.NewIdentity()
			if err != nil {
				t.Fatal(err)
			}
			if _, err := db.RegisterOwnerApprovalKeyLocal(ownerID, owner.Public()); err != nil {
				t.Fatal(err)
			}
			hubID, err := db.GetClientHubID()
			if err != nil {
				t.Fatal(err)
			}
			grant, err := owner.SignOwnerDeviceGrant(ownerID, "phone-fixture", device.Public(), hubID,
				e2ee.OwnerDevicePurposeControl, time.Now().Add(-time.Minute), time.Now().Add(time.Hour))
			if err != nil {
				t.Fatal(err)
			}
			if _, err := db.RegisterClientDeviceFromOwnerGrant(store.RegisterClientDeviceInput{
				OwnerID: ownerID, OwnerKeyID: owner.Public().ID, DeviceID: "phone-fixture",
				DevicePublic: device.Public(), OwnerDeviceGrant: grant,
			}); err != nil {
				t.Fatal(err)
			}
			if err := db.Close(); err != nil {
				t.Fatal(err)
			}
			binding := clientwire.Binding{HubID: hubID, OwnerID: ownerID, DeviceID: "phone-fixture",
				SessionEpoch: 1, HubKeyVersion: 1, DeviceKeyVersion: 1}
			public := manager.ClientControlPublicIdentity()
			route := clientwire.Route{Version: clientwire.Version,
				Direction: clientwire.DirectionRequest, HubID: hubID, OwnerID: ownerID,
				DeviceID: binding.DeviceID, SessionEpoch: 1, Sequence: 1,
				OperationID: "fixture-operation", Operation: "status.snapshot",
				SenderKeyID: device.Public().ID, SenderKeyVersion: 1,
				ReceiverKeyID: public.ID, ReceiverKeyVersion: 1}
			packet, err := clientwire.SealRequest(device, public, binding, route, []byte(`{}`))
			if err != nil {
				t.Fatal(err)
			}
			if err := run([]string{"--db", dbPath, "--mode", scenario.mode}, bytes.NewReader(packet)); err != nil {
				t.Fatal(err)
			}
			if scenario.mode == "uncertain" {
				ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
				if err := manager.Shutdown(ctx); err != nil {
					cancel()
					t.Fatal(err)
				}
				cancel()
				manager, err = control.New(control.Config{StateDir: state,
					WorkspaceRoot: filepath.Join(root, "workspace")})
				if err != nil {
					t.Fatal(err)
				}
			}
			handler := server.NewHandler(manager)
			recovered := httptest.NewRecorder()
			handler.ServeHTTP(recovered, httptest.NewRequest(http.MethodPost,
				"/v2/client/rpc/recover", bytes.NewReader(packet)))
			if recovered.Code != scenario.status {
				t.Fatalf("recovery status=%d want=%d", recovered.Code, scenario.status)
			}
			if scenario.status == http.StatusConflict {
				var failure struct {
					Code string `json:"code"`
				}
				if err := json.Unmarshal(recovered.Body.Bytes(), &failure); err != nil || failure.Code != scenario.code {
					t.Fatalf("recovery code=%q error=%v", failure.Code, err)
				}
			} else {
				opened, err := clientwire.OpenResponse(device, public, binding, recovered.Body.Bytes())
				if err != nil || opened.Route.Sequence != 1 {
					t.Fatalf("uncertain response cannot be opened: %v", err)
				}
				var notice struct {
					ErrorCode string `json:"error_code"`
				}
				if err := json.Unmarshal(opened.Plaintext, &notice); err != nil || notice.ErrorCode != scenario.code {
					t.Fatalf("uncertain notice=%q error=%v", notice.ErrorCode, err)
				}
			}
			duplicate := httptest.NewRecorder()
			handler.ServeHTTP(duplicate, httptest.NewRequest(http.MethodPost,
				"/v2/client/rpc", bytes.NewReader(packet)))
			if duplicate.Code != http.StatusConflict {
				t.Fatalf("interrupted operation was dispatched again: status=%d", duplicate.Code)
			}
		})
	}
}
