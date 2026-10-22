package main

import (
	"encoding/json"
	"strings"
	"testing"
	"time"

	wire "github.com/cicada-ai/cicada/internal/hubaccountwire"
)

func TestLocalCodexContextDomainMetadataCannotChangeTicketAuthority(t *testing.T) {
	var authority localCodexContextAuthority
	q := syntheticCodexContextIssue()
	now := time.Now().UTC()
	issued, err := authority.issue(q, "synthetic-original-binding", now)
	if err != nil {
		t.Fatal(err)
	}
	id := strings.Split(issued.Ticket, ".")[0]
	original := authority.live[id]
	changed := original
	changed.Context.VerificationProfile = LocalCodexContextProfileDomain
	changed.Context.LocalDomainVersion = 1
	changed.Context.LocalDomain = wire.LocalDomainSelection{PolicyID: strings.Repeat("a", 32), PolicyEpoch: 2, PolicyDigest: strings.Repeat("b", 64)}
	authority.live[id] = changed
	if _, err = authority.consume(syntheticCodexContextConsume(q, issued.Ticket), "synthetic-original-binding", now); err == nil {
		t.Fatal("domain metadata was changed without changing the HMAC")
	}
	authority.live[id] = original
	consumed, err := authority.consume(syntheticCodexContextConsume(q, issued.Ticket), "synthetic-original-binding", now)
	if err != nil {
		t.Fatal("refusal consumed the unchanged original", err)
	}
	raw, _ := json.Marshal(consumed.Context)
	if strings.Contains(string(raw), "local_domain") || strings.Contains(string(raw), "verification_profile") {
		t.Fatal("legacy context added unknown profile fields to old strict consumers")
	}
}

func TestLocalDomainEndpointRequestKeepsLegacyJSONAndExactValueRetry(t *testing.T) {
	legacy := syntheticLocalEndpointRequest("endpoint_register")
	raw, err := json.Marshal(legacy)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(raw), "local_domain") {
		t.Fatal("legacy intent serialization changed")
	}
	q := legacy
	q.LocalDomainVersion = 1
	q.LocalDomain = wire.LocalDomainSelection{PolicyID: strings.Repeat("b", 32), PolicyEpoch: 1, PolicyDigest: strings.Repeat("c", 64)}
	if q.validate() != nil {
		t.Fatal("valid selected domain context was refused")
	}
	raw, err = json.Marshal(q)
	if err != nil {
		t.Fatal(err)
	}
	var restored localEndpointRequest
	if json.Unmarshal(raw, &restored) != nil || restored != q {
		t.Fatal("persisted exact domain intent lost value equality after restart")
	}
	for _, op := range []string{"native_pair_join_named", "endpoint_leave", "endpoint_directory"} {
		changed := q
		changed.Operation = op
		if changed.validate() == nil {
			t.Fatal("domain selection entered a legacy/Pair operation")
		}
	}
	q.LocalDomainVersion = 2
	if q.validate() == nil {
		t.Fatal("unknown domain format version was accepted")
	}
}
