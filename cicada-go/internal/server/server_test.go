package server

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"

	"github.com/cicada-ai/cicada/internal/control"
	"github.com/cicada-ai/cicada/internal/e2ee"
)

func TestSignedConnectorWebhookIsDurable(t *testing.T) {
	root := t.TempDir()
	controlPlane, err := control.New(control.Config{
		StateDir: filepath.Join(root, "state"), WorkspaceRoot: filepath.Join(root, "workspace"),
		WebhookSecret: "connector-secret",
	})
	if err != nil {
		t.Fatal(err)
	}
	defer controlPlane.Shutdown(context.Background())
	payload := []byte(`{"subject":"hello"}`)
	mac := hmac.New(sha256.New, []byte("connector-secret"))
	_, _ = mac.Write(payload)
	request := httptest.NewRequest(http.MethodPost, "/v1/connectors/events", strings.NewReader(string(payload)))
	request.Header.Set("X-Cicada-Connector", "mail")
	request.Header.Set("X-Cicada-Event-ID", "mail-1")
	request.Header.Set("X-Cicada-Event-Type", "message.created")
	request.Header.Set("X-Cicada-Signature", "sha256="+hex.EncodeToString(mac.Sum(nil)))
	response := httptest.NewRecorder()
	NewHandler(controlPlane).ServeHTTP(response, request)
	if response.Code != http.StatusAccepted {
		t.Fatalf("webhook status=%d body=%s", response.Code, response.Body.String())
	}
	list := httptest.NewRequest(http.MethodGet, "/v1/connectors/events?connector=mail", nil)
	listResponse := httptest.NewRecorder()
	NewHandler(controlPlane).ServeHTTP(listResponse, list)
	if listResponse.Code != http.StatusOK || !strings.Contains(listResponse.Body.String(), "mail-1") {
		t.Fatalf("webhook event missing from list: status=%d body=%s", listResponse.Code, listResponse.Body.String())
	}
}

func TestSignedContactAnnouncementEndpoint(t *testing.T) {
	root := t.TempDir()
	controlPlane, err := control.New(control.Config{StateDir: filepath.Join(root, "state"), WorkspaceRoot: filepath.Join(root, "workspace")})
	if err != nil {
		t.Fatal(err)
	}
	defer controlPlane.Shutdown(context.Background())
	request := httptest.NewRequest(http.MethodPost, "/v1/identity/announcement", strings.NewReader(`{"label":"Alice"}`))
	request.Header.Set("content-type", "application/json")
	response := httptest.NewRecorder()
	NewHandler(controlPlane).ServeHTTP(response, request)
	if response.Code != http.StatusOK {
		t.Fatalf("announcement status=%d body=%s", response.Code, response.Body.String())
	}
	if _, label, err := e2ee.VerifyContactAnnouncement(response.Body.Bytes()); err != nil || label != "Alice" {
		t.Fatalf("invalid signed announcement body=%s err=%v label=%q", response.Body.String(), err, label)
	}
}

func TestFederationIngressMapsIdentityAndIsIdempotent(t *testing.T) {
	root := t.TempDir()
	bob, err := control.New(control.Config{StateDir: filepath.Join(root, "bob-state"), WorkspaceRoot: filepath.Join(root, "bob-workspace")})
	if err != nil {
		t.Fatal(err)
	}
	defer bob.Shutdown(context.Background())
	receiver := httptest.NewServer(NewHandler(bob))
	defer receiver.Close()
	alice, err := control.New(control.Config{
		StateDir: filepath.Join(root, "alice-state"), WorkspaceRoot: filepath.Join(root, "alice-workspace"),
		PeerRelayURL: receiver.URL + "/v1/federation/messages",
	})
	if err != nil {
		t.Fatal(err)
	}
	defer alice.Shutdown(context.Background())
	aliceContact, err := alice.CreateContact("Bob", bob.Identity())
	if err != nil {
		t.Fatal(err)
	}
	bobContact, err := bob.CreateContact("Alice", alice.Identity())
	if err != nil {
		t.Fatal(err)
	}
	outbound, err := alice.SendPeerMessage(aliceContact.ID, "relay must not see this plaintext", []byte("goal=federation"))
	if err != nil {
		t.Fatal(err)
	}
	delivered, err := alice.DeliverPeerMessage(outbound.ID)
	if err != nil || delivered.Status != "delivered" {
		t.Fatalf("direct federation delivery failed: message=%#v err=%v", delivered, err)
	}
	payload, err := json.Marshal(map[string]any{
		"id": outbound.ID, "contact_id": outbound.ContactID,
		"sender_id": outbound.SenderID, "recipient_id": outbound.RecipientID,
		"sequence": outbound.Sequence, "envelope": outbound.Envelope,
		"aad_base64": outbound.AAD,
	})
	if err != nil {
		t.Fatal(err)
	}
	handler := NewHandler(bob)
	post := func() *httptest.ResponseRecorder {
		request := httptest.NewRequest(http.MethodPost, "/v1/federation/messages", strings.NewReader(string(payload)))
		request.Header.Set("content-type", "application/json")
		response := httptest.NewRecorder()
		handler.ServeHTTP(response, request)
		return response
	}
	if _, err := bob.UpdateContact(bobContact.ID, "Alice", "revoked"); err != nil {
		t.Fatal(err)
	}
	duplicateResponse := post()
	if duplicateResponse.Code != http.StatusAccepted || strings.Contains(duplicateResponse.Body.String(), "relay must not see this plaintext") {
		t.Fatalf("duplicate federation ingress status=%d body=%s", duplicateResponse.Code, duplicateResponse.Body.String())
	}
	var receipt control.FederationReceipt
	if err := json.Unmarshal(duplicateResponse.Body.Bytes(), &receipt); err != nil || !receipt.Duplicate || receipt.TransportID != outbound.ID {
		t.Fatalf("invalid duplicate receipt: %#v err=%v", receipt, err)
	}
	var mismatched map[string]any
	if err := json.Unmarshal(payload, &mismatched); err != nil {
		t.Fatal(err)
	}
	mismatched["sequence"] = outbound.Sequence + 1
	mismatchedPayload, _ := json.Marshal(mismatched)
	mismatchRequest := httptest.NewRequest(http.MethodPost, "/v1/federation/messages", strings.NewReader(string(mismatchedPayload)))
	mismatchResponse := httptest.NewRecorder()
	handler.ServeHTTP(mismatchResponse, mismatchRequest)
	if mismatchResponse.Code != http.StatusBadRequest {
		t.Fatalf("unauthenticated transport sequence was accepted: status=%d body=%s", mismatchResponse.Code, mismatchResponse.Body.String())
	}
	messages, err := bob.PeerMessages(bobContact.ID)
	if err != nil || len(messages) != 1 || messages[0].TransportID != outbound.ID {
		t.Fatalf("federation ingress was not atomically idempotent: messages=%#v err=%v", messages, err)
	}
}

func TestPermissionAPIIsDurableAndDeletable(t *testing.T) {
	root := t.TempDir()
	controlPlane, err := control.New(control.Config{StateDir: filepath.Join(root, "state"), WorkspaceRoot: filepath.Join(root, "workspace")})
	if err != nil {
		t.Fatal(err)
	}
	defer controlPlane.Shutdown(context.Background())
	handler := NewHandler(controlPlane)
	create := httptest.NewRequest(http.MethodPost, "/v1/permissions", strings.NewReader(`{"subject_type":"contact","subject_id":"contact_bob","action":"peer.message","effect":"deny"}`))
	create.Header.Set("content-type", "application/json")
	createdResponse := httptest.NewRecorder()
	handler.ServeHTTP(createdResponse, create)
	if createdResponse.Code != http.StatusOK {
		t.Fatalf("permission create status=%d body=%s", createdResponse.Code, createdResponse.Body.String())
	}
	var permission struct {
		ID string `json:"id"`
	}
	if err := json.Unmarshal(createdResponse.Body.Bytes(), &permission); err != nil || permission.ID == "" {
		t.Fatalf("invalid permission response: %s err=%v", createdResponse.Body.String(), err)
	}
	list := httptest.NewRequest(http.MethodGet, "/v1/permissions?subject_type=contact&subject_id=contact_bob", nil)
	listResponse := httptest.NewRecorder()
	handler.ServeHTTP(listResponse, list)
	if listResponse.Code != http.StatusOK || !strings.Contains(listResponse.Body.String(), permission.ID) {
		t.Fatalf("permission list missing created rule: status=%d body=%s", listResponse.Code, listResponse.Body.String())
	}
	remove := httptest.NewRequest(http.MethodDelete, "/v1/permissions/"+permission.ID, nil)
	removeResponse := httptest.NewRecorder()
	handler.ServeHTTP(removeResponse, remove)
	if removeResponse.Code != http.StatusNoContent {
		t.Fatalf("permission delete status=%d body=%s", removeResponse.Code, removeResponse.Body.String())
	}
}

func TestConfiguredAPITokenProtectsControlRoutes(t *testing.T) {
	root := t.TempDir()
	controlPlane, err := control.New(control.Config{
		StateDir: filepath.Join(root, "state"), WorkspaceRoot: filepath.Join(root, "workspace"),
		APIToken: "test-api-token",
	})
	if err != nil {
		t.Fatal(err)
	}
	defer controlPlane.Shutdown(context.Background())
	handler := NewHandler(controlPlane)
	unauthorized := httptest.NewRequest(http.MethodGet, "/v1/machines", nil)
	unauthorizedResponse := httptest.NewRecorder()
	handler.ServeHTTP(unauthorizedResponse, unauthorized)
	if unauthorizedResponse.Code != http.StatusUnauthorized {
		t.Fatalf("unauthorized API request status=%d body=%s", unauthorizedResponse.Code, unauthorizedResponse.Body.String())
	}
	wrong := httptest.NewRequest(http.MethodGet, "/v1/machines", nil)
	wrong.Header.Set("Authorization", "Bearer wrong")
	wrongResponse := httptest.NewRecorder()
	handler.ServeHTTP(wrongResponse, wrong)
	if wrongResponse.Code != http.StatusUnauthorized {
		t.Fatalf("wrong-token API request status=%d body=%s", wrongResponse.Code, wrongResponse.Body.String())
	}
	authorized := httptest.NewRequest(http.MethodGet, "/v1/machines", nil)
	authorized.Header.Set("Authorization", "Bearer test-api-token")
	authorizedResponse := httptest.NewRecorder()
	handler.ServeHTTP(authorizedResponse, authorized)
	if authorizedResponse.Code != http.StatusOK {
		t.Fatalf("authorized API request status=%d body=%s", authorizedResponse.Code, authorizedResponse.Body.String())
	}
	health := httptest.NewRequest(http.MethodGet, "/healthz", nil)
	healthResponse := httptest.NewRecorder()
	handler.ServeHTTP(healthResponse, health)
	if healthResponse.Code != http.StatusOK {
		t.Fatalf("health probe should remain public: status=%d", healthResponse.Code)
	}
}
