package fabric

import "testing"

func TestNodeClaimWakeHintsCoalescePerSubscriber(t *testing.T) {
	service := &Service{}
	wake, unsubscribe := service.SubscribeNodeEvents("node-a")
	defer unsubscribe()
	other, unsubscribeOther := service.SubscribeNodeEvents("node-b")
	defer unsubscribeOther()

	for i := 0; i < 100; i++ {
		service.NotifyNodeClaimHint("node-a")
	}
	if len(wake) != 1 {
		t.Fatalf("wake hints did not coalesce to one pending signal: %d", len(wake))
	}
	select {
	case <-wake:
	default:
		t.Fatal("committed-work hint did not wake the selected Node")
	}
	if len(wake) != 0 || len(other) != 0 {
		t.Fatalf("wake channel retained or crossed scopes: selected=%d other=%d", len(wake), len(other))
	}
	service.NotifyNodeClaimHint("node-a")
	if len(wake) != 1 {
		t.Fatal("a later committed-work hint was lost after the prior hint was consumed")
	}
}
