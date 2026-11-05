package hubaccountwire

import (
	"bytes"
	"encoding/json"
	"testing"
)

func TestThreadCollaborationNodeNestedTTL(t *testing.T) {
	_, holder, acquire := threadCollaborationFixture()
	renew := GroupLockRenewRequest{Scope: acquire.Scope, Slot: 1, ExpectedVersion: 2, Generation: 1, Original: acquire.Original}
	for _, tc := range []struct {
		op   string
		body any
	}{
		{OperationGroupLocksAcquire, GroupLocksNodeAcquire{holder.EndpointID, acquire}},
		{OperationGroupLocksRenew, GroupLocksNodeRenew{holder.EndpointID, renew}},
	} {
		t.Run(tc.op, func(t *testing.T) {
			raw, _ := json.Marshal(tc.body)
			if _, err := DecodeThreadCollaborationNodeBody(tc.op, raw); err != nil {
				t.Fatal("omitted nested TTL rejected", err)
			}
			for name, value := range map[string]string{"null": "null", "zero": "0", "negative": "-1", "high": "3601", "fraction": "1.5", "string": "\"300\"", "overflow": "4294967296"} {
				t.Run(name, func(t *testing.T) {
					bad := bytes.Replace(raw, []byte(`"slot":1`), []byte(`"slot":1,"ttl_seconds":`+value), 1)
					if _, err := DecodeThreadCollaborationNodeBody(tc.op, bad); err == nil {
						t.Fatal("nested wire bypassed TTL refusal")
					}
				})
			}
		})
	}
}
