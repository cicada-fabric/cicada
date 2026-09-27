package telegram

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

type roundTripFunc func(*http.Request) (*http.Response, error)

func (fn roundTripFunc) RoundTrip(request *http.Request) (*http.Response, error) {
	return fn(request)
}

func TestGetUpdatesUsesOffsetAndCapsResponse(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/bot123:abc/getUpdates" || r.URL.Query().Get("offset") != "9" {
			t.Fatalf("unexpected Telegram request: %s", r.URL.String())
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"ok":true,"result":[{"update_id":9}]}`))
	}))
	defer server.Close()
	client, err := NewClient(server.URL, "123:abc", server.Client())
	if err != nil {
		t.Fatal(err)
	}
	client.PollWait = 0
	updates, err := client.GetUpdates(context.Background(), 9)
	if err != nil || len(updates) != 1 {
		t.Fatalf("unexpected updates=%v err=%v", updates, err)
	}
}

func TestNewClientRejectsUnsafeTokenAndURL(t *testing.T) {
	if _, err := NewClient("https://api.telegram.org", "token/with/slash", nil); err == nil {
		t.Fatal("unsafe token was accepted")
	}
	if _, err := NewClient("https://user:pass@example.com", "123:abc", nil); err == nil {
		t.Fatal("credential-bearing API URL was accepted")
	}
}

func TestGetUpdatesDoesNotLeakTokenInTransportError(t *testing.T) {
	const token = "123:super-secret"
	httpClient := &http.Client{Transport: roundTripFunc(func(request *http.Request) (*http.Response, error) {
		return nil, errors.New("dial failed for " + request.URL.String())
	})}
	client, err := NewClient("https://api.telegram.org", token, httpClient)
	if err != nil {
		t.Fatal(err)
	}
	_, err = client.GetUpdates(context.Background(), 0)
	if err == nil || strings.Contains(err.Error(), token) {
		t.Fatalf("transport error exposed Telegram token: %v", err)
	}
}
