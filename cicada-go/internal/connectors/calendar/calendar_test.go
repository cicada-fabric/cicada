package calendar

import (
	"strings"
	"testing"
)

func TestNormalizeICS(t *testing.T) {
	id, kind, payload, err := Normalize([]byte("BEGIN:VCALENDAR\r\nBEGIN:VEVENT\r\nUID:evt-1\r\nSUMMARY:Review\r\nDTSTART:20260916T100000Z\r\nEND:VEVENT\r\nEND:VCALENDAR\r\n"))
	if err != nil || id != "evt-1" || kind != "event.created" || !strings.Contains(string(payload), "Review") {
		t.Fatalf("calendar result id=%q kind=%q payload=%s err=%v", id, kind, payload, err)
	}
}

func TestNormalizeJSONRejectsUnknownType(t *testing.T) {
	if _, _, _, err := Normalize([]byte(`{"id":"evt-1","type":"credential.request"}`)); err == nil {
		t.Fatal("unknown calendar event type was accepted")
	}
}
