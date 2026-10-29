package main

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/cicada-ai/cicada/internal/e2ee"
	wire "github.com/cicada-ai/cicada/internal/hubaccountwire"
)

// This is a serialization bound, not synthetic permission evidence. Exercise
// the actual DTO/saved structs near the page byte limit, including HTML JSON
// escaping, a long local transcript path absent from the DTO, first map/entry
// allocation, and cross-page authorities already retained in S.
func TestEndpointGroupsCapacityRegistrationGrowthBound(t *testing.T) {
	for _, existing := range []bool{false, true} {
		s := machineNodeControlState{ManagedLocalDomainLeases: map[string]machineManagedLocalDomainLease{
			"synthetic-lease": {IntentID: strings.Repeat("a", 32), IntentDigest: strings.Repeat("b", 64), TranscriptPath: "/synthetic/" + strings.Repeat("<", 4096)},
		}}
		m := s.ManagedLocalDomainLeases["synthetic-lease"]
		d := wire.EndpointGroupsNodeDescribeResult{ContractRevision: wire.OwnerEndpointGroupsContractRevision,
			Registration:      wire.EndpointGroupsRegistrationAnchor{RegistrationDigest: strings.Repeat("c", 64)},
			RelationsRevision: 1<<63 - 1, ObservedAt: "2026-10-29T00:00:00.123456789Z", NextCursor: strings.Repeat("<", 256)}
		for i := 0; i < 31; i++ {
			d.Authorities = append(d.Authorities, wire.EndpointGroupCurrentEndpoint{Relation: wire.EndpointGroupRelation{GroupID: "synthetic-group"}, OwnerControl: e2ee.EndpointGroupOwnerControl{Mode: "DEFAULT", DenyReason: "NONE"}})
		}
		raw, err := json.Marshal(d)
		if err != nil {
			t.Fatal(err)
		}
		d.Registration.Registration.Workspace = strings.Repeat("<", (wire.MaxOwnerEndpointGroupsPageBytes-len(raw))/6)
		raw, _ = json.Marshal(d)
		if len(raw) > wire.MaxOwnerEndpointGroupsPageBytes || wire.MaxOwnerEndpointGroupsPageBytes-len(raw) >= 6 {
			t.Fatal("DTO did not reach canonical page bound", len(raw))
		}
		r := machineEndpointGroupsRegistration{LeaseID: "synthetic-lease", IntentID: m.IntentID, IntentDigest: m.IntentDigest, TranscriptPath: m.TranscriptPath, LocalAccessRevision: 1}
		if existing {
			r.Anchor = d.Registration
			r.Authorities = []wire.EndpointGroupCurrentEndpoint{{Relation: wire.EndpointGroupRelation{GroupID: "synthetic-earlier-page"}}}
			s.EndpointGroupsRegistrations = map[string]machineEndpointGroupsRegistration{d.Registration.RegistrationDigest: r}
		}
		before, _ := json.Marshal(s)
		bound, err := endpointGroupsRegistrationGrowth(s)
		if err != nil {
			t.Fatal(err)
		}
		r.Anchor, r.RelationsRevision, r.ObservedAt, r.RelationsCursor = d.Registration, d.RelationsRevision, d.ObservedAt, d.NextCursor
		r.Authorities = append(r.Authorities, d.Authorities...)
		r.LocalAccessRevision, r.LocallyOffline = 1<<63-1, true
		r.KeyPrepareGenerations = map[string]uint64{strings.Repeat("f", 32) + ".9223372036854775807.9223372036854775807": 1<<63 - 1}
		if s.EndpointGroupsRegistrations == nil {
			s.EndpointGroupsRegistrations = make(map[string]machineEndpointGroupsRegistration)
		}
		s.EndpointGroupsRegistrations[d.Registration.RegistrationDigest] = r
		after, _ := json.Marshal(s)
		if growth := len(after) - len(before); growth > bound {
			t.Fatal("saved authority/local metadata exceeded reserved growth", existing, growth, bound)
		}
		t.Logf("CLOSED_REGISTRATION_GROWTH existing_page=%t page_bytes=%d actual_growth=%d reserved_growth=%d authority_count=%d", existing, len(raw), len(after)-len(before), bound, len(r.Authorities))
	}
}
