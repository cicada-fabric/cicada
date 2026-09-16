package server

import (
	"context"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/cicada-ai/cicada/internal/control"
)

func TestDirectoryAnnouncementAndRendezvousEndpoints(t *testing.T) {
	root := t.TempDir()
	peer, err := control.New(control.Config{StateDir: filepath.Join(root, "peer-state"), WorkspaceRoot: filepath.Join(root, "peer-workspace")})
	if err != nil {
		t.Fatal(err)
	}
	defer peer.Shutdown(context.Background())
	announcement, err := peer.SignDirectoryAnnouncement("Peer", []string{"https://peer.example/federation"}, time.Now().UTC().Add(time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	controlPlane, err := control.New(control.Config{StateDir: filepath.Join(root, "state"), WorkspaceRoot: filepath.Join(root, "workspace")})
	if err != nil {
		t.Fatal(err)
	}
	defer controlPlane.Shutdown(context.Background())
	handler := NewHandler(controlPlane)
	receive := httptest.NewRequest(http.MethodPost, "/v1/rendezvous", strings.NewReader(`{"announcement":`+string(announcement)+`}`))
	receive.Header.Set("content-type", "application/json")
	receiveResponse := httptest.NewRecorder()
	handler.ServeHTTP(receiveResponse, receive)
	if receiveResponse.Code != http.StatusAccepted {
		t.Fatalf("rendezvous status=%d body=%s", receiveResponse.Code, receiveResponse.Body.String())
	}
	list := httptest.NewRequest(http.MethodGet, "/v1/directory/records", nil)
	listResponse := httptest.NewRecorder()
	handler.ServeHTTP(listResponse, list)
	if listResponse.Code != http.StatusOK || !strings.Contains(listResponse.Body.String(), "peer.example") {
		t.Fatalf("directory list status=%d body=%s", listResponse.Code, listResponse.Body.String())
	}
}
