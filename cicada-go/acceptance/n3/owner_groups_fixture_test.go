package n3_test

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"regexp"
	"testing"
	"time"
)

// Inputs and observations for the existing N3 driver. These helpers neither
// implement the product protocol nor create an accepted Owner/Group authority.
// The actual runtime adapter is deliberately absent until formal delivery.
type ownerGroupsFault struct {
	ID            string `json:"id"`
	Path          string `json:"path"`
	Method        string `json:"method"`
	NodeOperation string `json:"node_operation"`
	Mode          string `json:"mode"`
	Count         int    `json:"count"`
}

type ownerGroupsCase struct {
	ID             string   `json:"id"`
	Observations   []string `json:"observations"`
	Faults         []string `json:"faults"`
	NegativeInputs []string `json:"negative_inputs"`
	Deterministic  []string `json:"deterministic_observations,omitempty"`
	NotRun         []string `json:"not_run,omitempty"`
}

type ownerGroupsInputs struct {
	Format           string             `json:"format"`
	ContractRevision string             `json:"contract_revision"`
	Status           string             `json:"status"`
	Faults           []ownerGroupsFault `json:"faults"`
	Cases            []ownerGroupsCase  `json:"cases"`
}

func readOwnerGroupsInputs(t *testing.T) ownerGroupsInputs {
	t.Helper()
	path := "/qa/scripts/fixtures/native-pair/owner_groups_cases.json"
	if _, err := os.Stat(path); os.IsNotExist(err) {
		path = filepath.Join("..", "..", "..", "scripts", "fixtures", "native-pair", "owner_groups_cases.json")
	}
	raw := must(os.ReadFile(path))
	if len(raw) > 64<<10 {
		t.Fatal("owned Group fault inputs exceed the fixture bound")
	}
	d := json.NewDecoder(bytes.NewReader(raw))
	d.DisallowUnknownFields()
	var plan ownerGroupsInputs
	if d.Decode(&plan) != nil || d.Decode(new(any)) != io.EOF ||
		plan.Format != "cicada.acceptance.owner-groups-inputs.v1" ||
		plan.ContractRevision != "owner-endpoint-groups-v1" || plan.Status != "PREPARED_NOT_EXECUTED" || len(plan.Cases) != 8 {
		t.Fatal("owned Group fault inputs differ from the reviewed preparation")
	}
	return plan
}

func armOwnerGroupsFault(t *testing.T, p *faultProxy, id string) (<-chan struct{}, func()) {
	t.Helper()
	for _, f := range readOwnerGroupsInputs(t).Faults {
		if f.ID != id {
			continue
		}
		if f.Method != http.MethodPost || f.Count != 1 ||
			(f.Path != "/v2/owner/endpoint-groups/apply" && f.Path != "/v2/node/control/rpc") ||
			(f.Path == "/v2/node/control/rpc" && f.NodeOperation != "node.endpoint_groups.key_complete" && f.NodeOperation != "node.endpoint_groups.renew") ||
			(f.Path != "/v2/node/control/rpc" && f.NodeOperation != "") {
			t.Fatal("Group fault attempted an unreviewed target or operation")
		}
		switch f.Mode {
		case "before-forward", "drop-after-response", "unsigned-403", "corrupt-response", "hold-before-forward":
		default:
			t.Fatal("unreviewed Group fault mode would silently forward the request")
		}
		return p.armMatch(f.Path, f.Method, f.NodeOperation, f.Mode, f.Count)
	}
	t.Fatal("unknown Group fault input")
	return nil, nil
}

// Call only after the actual actor, crypto, TCP and persistent-state assertions
// for this case have completed. Input definitions are never auto-emitted as facts.
func observeOwnerGroupsCase(t *testing.T, name string, observed map[string]bool) {
	t.Helper()
	for _, c := range readOwnerGroupsInputs(t).Cases {
		if c.ID != name {
			continue
		}
		if len(observed) != len(c.Observations) {
			t.Fatal("Group case has missing or foreign observations")
		}
		for _, key := range c.Observations {
			if !observed[key] {
				t.Fatal("Group case did not establish a required observation")
			}
		}
		raw := must(json.Marshal(map[string]any{"case": name, "observed": observed}))
		t.Log("OWNER_GROUPS_FACTS " + string(raw))
		return
	}
	t.Fatal("unknown Group acceptance case")
}

type ownerGroupsLeaseWitness struct {
	started        time.Time // time.Now retains the parent's real monotonic clock.
	originalExpiry time.Time
}

type ownerGroupsIdentity struct {
	SID             string `json:"native_session_id"`
	Endpoint        string `json:"endpoint_id"`
	Principal       string `json:"principal_id"`
	Workspace       string `json:"workspace"`
	NodeID          string `json:"node_id"`
	BindingID       string `json:"binding_id"`
	BindingEpoch    uint64 `json:"binding_epoch"`
	PublicKeySHA256 string `json:"endpoint_public_key_sha256"`
}

var ownerGroupsSIDPattern = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`)

// Capture before mutation and after M6, before the intentional root revocations
// in M7. Group-scoped changes must not replace these original identities.
func observeOwnerGroupsIdentities(t *testing.T, before, after []ownerGroupsIdentity) {
	t.Helper()
	if len(before) != 4 || len(after) != 4 {
		t.Fatal("Group acceptance did not retain four original native actors")
	}
	index := func(values []ownerGroupsIdentity) map[string]ownerGroupsIdentity {
		result := make(map[string]ownerGroupsIdentity)
		endpoints := make(map[string]bool)
		for _, actor := range values {
			if !ownerGroupsSIDPattern.MatchString(actor.SID) || actor.Endpoint == "" || actor.Principal == "" ||
				actor.Workspace == "" || actor.NodeID != before[0].NodeID || actor.NodeID == "" ||
				actor.BindingID == "" || actor.BindingEpoch == 0 || len(actor.PublicKeySHA256) != 64 ||
				result[actor.SID].SID != "" || endpoints[actor.Endpoint] {
				t.Fatal("Group identity witness has missing, merged or foreign actor coordinates")
			}
			result[actor.SID], endpoints[actor.Endpoint] = actor, true
		}
		return result
	}
	if !reflect.DeepEqual(index(before), index(after)) {
		t.Fatal("Group-only mutations replaced an original native identity/key/binding")
	}
	raw := must(json.Marshal(map[string]any{"before": before, "after_group_operations": after}))
	t.Log("OWNER_GROUPS_IDENTITIES " + string(raw))
}

func startOwnerGroupsLeaseWitness(t *testing.T, originalExpiry string) ownerGroupsLeaseWitness {
	t.Helper()
	w := ownerGroupsLeaseWitness{started: time.Now(), originalExpiry: must(time.Parse(time.RFC3339Nano, originalExpiry))}
	if !w.originalExpiry.After(w.started) {
		t.Fatal("Group lease witness did not start before the actual original deadline")
	}
	return w
}

// No caller-provided elapsed value or synthetic clock can establish M5. The
// parent survives child Node/MCP restarts and must actually pass the old deadline.
func (w ownerGroupsLeaseWitness) observeAfter(t *testing.T, renewedExpiry string) {
	t.Helper()
	after := time.Now()
	renewed := must(time.Parse(time.RFC3339Nano, renewedExpiry))
	if !after.After(w.originalExpiry) || !renewed.After(after) || w.started.IsZero() || after.Sub(w.started) <= 0 {
		t.Fatal("G2 did not retain a live renewed lease beyond the actual original boundary")
	}
	raw := must(json.Marshal(map[string]any{
		"clock": "REAL_WALL_AND_MONOTONIC", "source": "G2_OWNER_EXPLICIT",
		"baseline_at":               w.started.UTC().Format(time.RFC3339Nano),
		"original_lease_expires_at": w.originalExpiry.UTC().Format(time.RFC3339Nano),
		"after_boundary_at":         after.UTC().Format(time.RFC3339Nano),
		"renewed_lease_expires_at":  renewed.UTC().Format(time.RFC3339Nano),
		"monotonic_elapsed_seconds": after.Sub(w.started).Seconds(),
	}))
	t.Log("OWNER_GROUPS_LEASE " + string(raw))
}

// Synthetic TCP harness self-check only. It cannot satisfy any M1-M8 case and
// emits neither OWNER_GROUPS_FACTS nor a product acceptance summary.
func TestN3OwnerGroupsFaultRouting(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}))
	defer upstream.Close()
	p := newFaultProxy(t, upstream.URL)
	_, release := armOwnerGroupsFault(t, p, "renew-lost-response")
	defer release()
	for index, operation := range []string{"node.endpoint_groups.key_complete", "node.endpoint_groups.renew", "node.endpoint_groups.renew"} {
		raw := must(json.Marshal(map[string]any{"route": map[string]any{"operation": operation}}))
		response, err := http.Post(p.server.URL+"/v2/node/control/rpc", "application/json", bytes.NewReader(raw))
		if response != nil {
			response.Body.Close()
		}
		if (index == 1 && err == nil) || (index != 1 && (err != nil || response == nil || response.StatusCode != http.StatusNoContent)) {
			t.Fatal("Node RPC fault was not isolated to the one selected renewal")
		}
	}
	trace := p.snapshot()
	if len(trace) != 3 || !trace[0].Forwarded || !trace[1].Forwarded || !trace[2].Forwarded {
		t.Fatal("owned operation-specific fault did not retain its exact forwarding trace")
	}
	p.mu.Lock()
	remaining := p.count
	p.mu.Unlock()
	if remaining != 0 {
		t.Fatal("operation-specific fault was not consumed exactly once")
	}
	t.Log("OWNER_GROUPS_SYNTHETIC_FAULT_PROXY_ONLY product_M1_M8=NOT_RUN")
}
