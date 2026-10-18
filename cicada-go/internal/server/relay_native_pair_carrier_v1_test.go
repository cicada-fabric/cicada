package server

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	wire "github.com/cicada-ai/cicada/internal/hubaccountwire"
	"github.com/cicada-ai/cicada/internal/store"
)

// Called with actual signed carriers from the real N2/N3/dual-consent TCP
// ceremony. This separate HTTP fixture tests byte rendering only; it does not
// create or publish Store authority, execute SIDs, or replace the Tx gates.
func assertNativePairCarrierHTTPBoundary(t *testing.T, name string, actual any) {
	t.Helper()
	t.Run(name+"_http_bytes", func(t *testing.T) {
		baseline, err := json.Marshal(actual)
		if err != nil {
			t.Fatal(err)
		}
		var clone any
		var grantID *string
		switch actual.(type) {
		case *store.SameGroupSealedV1PeerKey:
			v := new(store.SameGroupSealedV1PeerKey)
			if err = json.Unmarshal(baseline, v); err != nil {
				t.Fatal(err)
			}
			clone = v
			grantID = &v.Receiver.Grant.ID
		case *store.SameGroupSealedV1DeliveryAuthorization:
			v := new(store.SameGroupSealedV1DeliveryAuthorization)
			if err = json.Unmarshal(baseline, v); err != nil {
				t.Fatal(err)
			}
			clone = v
			grantID = &v.Receiver.Grant.ID
		default:
			t.Fatal("missing exact typed actual carrier")
		}
		if len(baseline) >= wire.MaxNativePairCarrierBytes {
			t.Fatal("unexpected initial carrier size")
		}
		*grantID += strings.Repeat("s", wire.MaxNativePairCarrierBytes-len(baseline))
		exact, err := json.Marshal(clone)
		if err != nil || len(exact) != wire.MaxNativePairCarrierBytes || wire.ValidateNativePairCarrierSize(clone) != nil {
			t.Fatal("complete typed exact-limit fixture invalid", len(exact), err)
		}
		call := func(want int) []byte {
			h := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { writeSameGroupSealedV1Carrier(w, http.StatusOK, clone) }))
			defer h.Close()
			response, e := h.Client().Get(h.URL)
			if e != nil {
				t.Fatal(e)
			}
			defer response.Body.Close()
			raw, e := io.ReadAll(io.LimitReader(response.Body, wire.MaxNativePairCarrierBytes+2))
			if e != nil || response.StatusCode != want {
				t.Fatal("actual HTTP carrier boundary", response.StatusCode, want, e)
			}
			return raw
		}
		raw := call(http.StatusOK)
		if !bytes.Equal(raw, exact) || len(raw) != wire.MaxNativePairCarrierBytes || bytes.HasSuffix(raw, []byte("\n")) {
			t.Fatal("actual HTTP body differs from exact Store Marshal bytes", len(raw))
		}
		// The old Encoder would append LF here and exceed the consumer's bound.
		*grantID += "s"
		plusOne, _ := json.Marshal(clone)
		if len(plusOne) != wire.MaxNativePairCarrierBytes+1 || wire.ValidateNativePairCarrierSize(clone) == nil {
			t.Fatal("limit+1 fixture invalid")
		}
		rejected := call(http.StatusNotFound)
		if bytes.Contains(rejected, []byte(`"native_pair_evidence"`)) || bytes.Contains(rejected, []byte(`"native_pair_current"`)) || bytes.HasPrefix(rejected, exact[:128]) {
			t.Fatal("oversize HTTP response partially published carrier")
		}
		t.Logf("synthetic actual typed %s HTTP exact=%d accepted; +1=%d rejected before publication", name, len(raw), len(plusOne))
	})
}

func TestNativePairCarrierHTTPKeepsLegacyEncoderAndRejectsIncompletePair(t *testing.T) {
	for _, carrier := range []any{&store.SameGroupSealedV1PeerKey{}, &store.SameGroupSealedV1DeliveryAuthorization{}} {
		response := httptest.NewRecorder()
		writeSameGroupSealedV1Carrier(response, http.StatusOK, carrier)
		encoded, _ := json.Marshal(carrier)
		if response.Code != http.StatusOK || !bytes.Equal(response.Body.Bytes(), append(encoded, '\n')) {
			t.Fatal("ordinary Group Encoder changed")
		}
	}
	incomplete := &store.SameGroupSealedV1PeerKey{NativePairCurrent: &wire.NativePairPeerCurrent{State: "CURRENT"}}
	response := httptest.NewRecorder()
	writeSameGroupSealedV1Carrier(response, http.StatusOK, incomplete)
	if response.Code != http.StatusNotFound || bytes.Contains(response.Body.Bytes(), []byte(`"native_pair_current"`)) {
		t.Fatal("missing signed evidence silently downgraded or partially published")
	}
}
