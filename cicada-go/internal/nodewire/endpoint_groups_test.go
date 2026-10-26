package nodewire

import (
	"bytes"
	"testing"
)

func TestEndpointGroupsReconcileHasExactAuthenticatedRequestCeiling(t *testing.T) {
	node, hub, binding, route := testBinding(t)
	route.Operation = "node.endpoint_groups.reconcile"
	body := bytes.Repeat([]byte("S"), MaxEndpointGroupsReconcilePlaintextBytes)
	packet, err := SealRequest(node, hub.Public(), binding, route, body)
	if err != nil {
		t.Fatal(err)
	}
	if opened, err := OpenRequest(hub, node.Public(), binding, packet); err != nil || !bytes.Equal(opened.Plaintext, body) {
		t.Fatal("exact scoped request ceiling", err)
	}
	if _, err := SealRequest(node, hub.Public(), binding, route, append(body, 'S')); err == nil {
		t.Fatal("oversized scoped request accepted")
	}
	for _, op := range []string{"node.endpoint_groups.renew", "node.endpoint_groups.reconcile.extra", "node.native_pair.reconcile", "node.jobs.list"} {
		other := route
		other.Operation = op
		if _, err := SealRequest(node, hub.Public(), binding, other, body[:MaxRequestPlaintextBytes+1]); err == nil {
			t.Fatal("unrelated operation borrowed large body")
		}
	}
}
