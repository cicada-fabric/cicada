package server

import (
	"bytes"
	"net/http"
	"net/http/httptest"
	"testing"

	fabricpkg "github.com/cicada-ai/cicada/internal/fabric"
)

func TestSealedNodeRoutesRequireCurrentNodeIdentityAndRejectCallerRouteClaims(t *testing.T) {
	service, persistence, _ := newRelayNodeTestService(t)
	nodeToken, nodeDigest, err := fabricpkg.NewNodeCredential()
	if err != nil {
		t.Fatal(err)
	}
	bindRelayNodeTestCredential(t, persistence, "node-sealed", nodeDigest)
	handler := NewFabricHandler(service, "management-token")
	call := func(path, authorization, body string) *httptest.ResponseRecorder {
		t.Helper()
		response := httptest.NewRecorder()
		request := httptest.NewRequest(http.MethodPost, path, bytes.NewBufferString(body))
		request.Header.Set("Authorization", authorization)
		handler.ServeHTTP(response, request)
		return response
	}
	base := "/v2/relay/nodes/node-sealed/sealed/"
	for _, operation := range []string{"send", "ask", "reply", "claim"} {
		for _, auth := range []string{"", "Bearer management-token", "CicadaNode invalid"} {
			if result := call(base+operation, auth, `{}`); result.Code != http.StatusUnauthorized {
				t.Fatalf("%s accepted non-Node identity %q: %d %s", operation, auth, result.Code, result.Body.String())
			}
		}
		if result := call("/v2/relay/nodes/other/sealed/"+operation, "CicadaNode "+nodeToken, `{}`); result.Code != http.StatusForbidden {
			t.Fatalf("%s accepted another Node ID: %d %s", operation, result.Code, result.Body.String())
		}
	}
	if result := call(base+"send", "CicadaNode "+nodeToken,
		`{"link_id":"link","message_id":"msg","data_scope":"scope","ciphertext":"YQ==","sender_endpoint_id":"forged"}`); result.Code != http.StatusBadRequest {
		t.Fatalf("sealed send accepted caller route identity: %d %s", result.Code, result.Body.String())
	}
	if result := call(base+"ask", "CicadaNode "+nodeToken,
		`{"link_id":"link","message_id":"msg","request_id":"rq","data_scope":"scope","expires_at":"2027-01-01T00:00:00Z","ciphertext":"YQ==","sender_endpoint_id":"forged"}`); result.Code != http.StatusBadRequest {
		t.Fatalf("sealed ask accepted caller route identity: %d %s", result.Code, result.Body.String())
	}
	if result := call(base+"reply", "CicadaNode "+nodeToken,
		`{"request_id":"rq","message_id":"msg","data_scope":"scope","ciphertext":"YQ==","user_approved":true}`); result.Code != http.StatusBadRequest {
		t.Fatalf("sealed reply accepted caller approval claim: %d %s", result.Code, result.Body.String())
	}
	for _, path := range []string{base + "requests/rq_missing", base + "requests/rq_missing/cancel"} {
		method := http.MethodGet
		if bytes.HasSuffix([]byte(path), []byte("/cancel")) {
			method = http.MethodPost
		}
		for _, auth := range []string{"", "Bearer management-token", "CicadaNode invalid"} {
			response := httptest.NewRecorder()
			request := httptest.NewRequest(method, path, bytes.NewBufferString(`{}`))
			request.Header.Set("Authorization", auth)
			handler.ServeHTTP(response, request)
			if response.Code != http.StatusUnauthorized {
				t.Fatalf("sealed request status/cancel accepted non-Node identity: %s %s %d", path, auth, response.Code)
			}
		}
		response := httptest.NewRecorder()
		request := httptest.NewRequest(method, path, bytes.NewBufferString(`{}`))
		request.Header.Set("Authorization", "CicadaNode "+nodeToken)
		handler.ServeHTTP(response, request)
		if response.Code != http.StatusNotFound {
			t.Fatalf("unknown sealed request leaked across Node route: %s %d %s", path, response.Code, response.Body.String())
		}
	}
	if result := call(base+"send", "CicadaNode "+nodeToken,
		`{"link_id":"missing-link","message_id":"msg","data_scope":"scope","ciphertext":"YQ=="}`); result.Code != http.StatusForbidden {
		t.Fatalf("sealed send accepted an unapproved Link: %d %s", result.Code, result.Body.String())
	}
	if result := call(base+"claim", "CicadaNode "+nodeToken,
		`{"consumer_id":"sealed-node"}`); result.Code != http.StatusOK || !bytes.Contains(result.Body.Bytes(), []byte(`"deliveries":[]`)) {
		t.Fatalf("authorized empty sealed claim: %d %s", result.Code, result.Body.String())
	}
}
