package appcore

import (
	"context"
	"errors"
	"net/http"
	"testing"
)

type connectionHTTPProbe struct{ calls, closed int }

func (p *connectionHTTPProbe) Do(*http.Request) (*http.Response, error) {
	p.calls++
	return nil, errors.New("synthetic unavailable transport")
}

func (p *connectionHTTPProbe) CloseIdleConnections() { p.closed++ }

func TestDirectConnectionResetClosesPoolAndNeverFallsBack(t *testing.T) {
	legacy, direct := new(connectionHTTPProbe), new(connectionHTTPProbe)
	controller, err := NewController(Config{HTTP: legacy})
	if err != nil {
		t.Fatal(err)
	}
	c := controller.(*nativeController)
	c.directConnection, c.connectionHTTP = true, direct
	if err := c.resetConnection(); err != nil {
		t.Fatal(err)
	}
	if direct.closed != 1 || legacy.closed != 0 {
		t.Fatal("connection reset did not close only its active pool")
	}
	if _, _, err := c.verifyHub(context.Background(), HubConnectionCard{Origin: "https://synthetic-logical.invalid"}); err == nil || legacy.calls != 0 || direct.calls != 0 {
		t.Fatal("missing direct transport fell back to another client")
	}
	if err := controller.Close(); err != nil {
		t.Fatal(err)
	}
	if legacy.closed != 0 || direct.closed != 1 {
		t.Fatal("closing a failed direct connection selected a legacy pool")
	}
}

func TestControllerCloseClosesTheActiveConnectionPool(t *testing.T) {
	for _, directMode := range []bool{false, true} {
		legacy, direct := new(connectionHTTPProbe), new(connectionHTTPProbe)
		controller, err := NewController(Config{HTTP: legacy})
		if err != nil {
			t.Fatal(err)
		}
		c := controller.(*nativeController)
		if directMode {
			c.directConnection, c.connectionHTTP = true, direct
		}
		if err := controller.Close(); err != nil {
			t.Fatal(err)
		}
		if err := controller.Close(); err != nil {
			t.Fatal(err)
		}
		if directMode && (direct.closed != 1 || legacy.closed != 0) || !directMode && (legacy.closed != 1 || direct.closed != 0) {
			t.Fatal("controller close did not release exactly its active pool")
		}
	}
}
