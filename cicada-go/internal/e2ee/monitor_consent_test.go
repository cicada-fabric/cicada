package e2ee

import (
	"crypto/sha256"
	"encoding/hex"
	"strings"
	"testing"
)

func syntheticMonitorConsentScope() MonitorBroadcastConsentScope {
	card := func(endpoint string) MonitorBroadcastConsentEndpoint {
		return MonitorBroadcastConsentEndpoint{EndpointID: endpoint, PrincipalID: "principal_synthetic", OwnerID: "owner_synthetic",
			NodeID: "node_synthetic", MembershipRevision: 2, GroupJoinRevision: 3,
			BindingID: "binding_synthetic", BindingEpoch: 4, KeyID: "key_" + endpoint,
			KeyVersion: 5, KeyFingerprint: "sha256:" + strings.Repeat("a", 64), KeyProofDigest: strings.Repeat("b", 64)}
	}
	return MonitorBroadcastConsentScope{Version: MonitorBroadcastConsentVersion,
		BroadcastID: "bc_synthetic", GroupID: "group_synthetic", GroupRevision: 1,
		Source: card("source_synthetic"), Recipients: []MonitorBroadcastConsentEndpoint{card("recipient_a"), card("recipient_b")}}
}

func TestMonitorConsentDigestBindsOrderKeyAndRevisions(t *testing.T) {
	scope := syntheticMonitorConsentScope()
	digest, err := MonitorBroadcastConsentDigest(scope)
	if err != nil || len(digest) != 64 {
		t.Fatalf("consent digest: %s %v", digest, err)
	}
	modified := scope
	modified.Recipients = append([]MonitorBroadcastConsentEndpoint(nil), scope.Recipients...)
	modified.Recipients[1].KeyFingerprint = "sha256:" + strings.Repeat("c", 64)
	changed, err := MonitorBroadcastConsentDigest(modified)
	if err != nil || changed == digest {
		t.Fatal("recipient key substitution did not change consent")
	}
	modified = scope
	modified.Recipients = append([]MonitorBroadcastConsentEndpoint(nil), scope.Recipients...)
	modified.Recipients[0].BindingEpoch++
	changed, err = MonitorBroadcastConsentDigest(modified)
	if err != nil || changed == digest {
		t.Fatal("binding epoch did not change consent")
	}
	modified = scope
	modified.Recipients = []MonitorBroadcastConsentEndpoint{scope.Recipients[1], scope.Recipients[0]}
	if _, err := MonitorBroadcastConsentDigest(modified); err == nil {
		t.Fatal("reordered roster accepted")
	}
	modified.Recipients = nil
	if _, err := MonitorBroadcastConsentDigest(modified); err == nil {
		t.Fatal("null roster accepted")
	}
	modified.Recipients = []MonitorBroadcastConsentEndpoint{}
	if _, err := MonitorBroadcastConsentDigest(modified); err != nil {
		t.Fatal("empty roster rejected", err)
	}
}

func TestMonitorConsentEnvelopeBindsConfirmSequenceAndBodyCap(t *testing.T) {
	client, err := NewIdentity()
	if err != nil {
		t.Fatal(err)
	}
	monitor, err := NewIdentity()
	if err != nil {
		t.Fatal(err)
	}
	body := []byte("synthetic consent body")
	context := monitorBroadcastTestContext(monitor.Public(), body)
	scope := syntheticMonitorConsentScope()
	digest, err := MonitorBroadcastConsentDigest(scope)
	if err != nil {
		t.Fatal(err)
	}
	context.ConsentSHA256, context.ConfirmRequestSequence = digest, 17
	wire, err := SealMonitorBroadcast(client, monitor.Public(), context, body, 17)
	if err != nil {
		t.Fatal(err)
	}
	if sequence, err := VerifyMonitorBroadcast(wire, client.Public(), monitor.Public(), context); err != nil || sequence != 17 {
		t.Fatalf("verify consent envelope: %d %v", sequence, err)
	}
	for _, change := range []func(*MonitorBroadcastContext){
		func(c *MonitorBroadcastContext) { c.ConsentSHA256 = strings.Repeat("0", 64) },
		func(c *MonitorBroadcastContext) { c.ConfirmRequestSequence++ },
		func(c *MonitorBroadcastContext) { c.ConsentSHA256 = ""; c.ConfirmRequestSequence = 0 },
	} {
		bad := context
		change(&bad)
		if _, err := VerifyMonitorBroadcast(wire, client.Public(), monitor.Public(), bad); err == nil {
			t.Fatal("changed consent or sequence verified")
		}
	}
	if _, err := SealMonitorBroadcast(client, monitor.Public(), context, body, 18); err == nil {
		t.Fatal("different inner sequence sealed")
	}
	tooLarge := []byte(strings.Repeat("x", MonitorBroadcastClientBodyMaxBytes+1))
	sum := sha256.Sum256(tooLarge)
	context.BodySHA256 = hex.EncodeToString(sum[:])
	if _, err := SealMonitorBroadcast(client, monitor.Public(), context, tooLarge, 17); err == nil {
		t.Fatal("oversized Client body sealed")
	}
}
