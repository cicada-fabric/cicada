package server

import (
	"net/http/httptest"
	"strings"
	"testing"
)

func TestReadJSONRequiresExactlyOneTopLevelValue(t *testing.T) {
	tests := []struct {
		name    string
		body    string
		wantErr bool
	}{
		{name: "one object with whitespace", body: "{\"value\":1} \n\t"},
		{name: "second object", body: `{"value":1}{"value":2}`, wantErr: true},
		{name: "second null", body: `{"value":1} null`, wantErr: true},
		{name: "trailing data", body: `{"value":1} garbage`, wantErr: true},
	}
	for _, testCase := range tests {
		t.Run(testCase.name, func(t *testing.T) {
			request := httptest.NewRequest("POST", "/", strings.NewReader(testCase.body))
			var value struct {
				Value int `json:"value"`
			}
			err := readJSON(request, &value)
			if testCase.wantErr && err == nil {
				t.Fatal("accepted multiple JSON values or trailing data")
			}
			if !testCase.wantErr && err != nil {
				t.Fatalf("valid single JSON value rejected: %v", err)
			}
			if !testCase.wantErr && value.Value != 1 {
				t.Fatalf("decoded value=%d, want 1", value.Value)
			}
		})
	}
}
