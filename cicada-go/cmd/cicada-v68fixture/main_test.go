package main

import (
	"bytes"
	"encoding/json"
	"github.com/cicada-ai/cicada/internal/clientwire"
	"github.com/cicada-ai/cicada/internal/e2ee"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/cicada-ai/cicada/internal/fabric"
	"github.com/cicada-ai/cicada/internal/nodekeys"
	"github.com/cicada-ai/cicada/internal/store"
)

func TestNativeFixtureThreadInputsFailClosed(t *testing.T) {
	a := "01999d8a-2833-7356-b50e-1023a845852e"
	b := "01999d8a-2833-7356-b50e-1023a845852f"
	for _, pair := range [][2]string{{"", ""}, {a, b}} {
		if err := validateNativeThreads(pair[0], pair[1]); err != nil {
			t.Fatal(err)
		}
	}
	for _, pair := range [][2]string{{a, ""}, {"", b}, {a, a}, {"thread_synthetic", b},
		{strings.ToUpper(a), b}, {" " + a, b}, {"00000000-0000-0000-0000-000000000000", b}} {
		if err := validateNativeThreads(pair[0], pair[1]); err == nil {
			t.Fatal("unsafe or incomplete native fixture coordinates were accepted")
		}
	}
}

func TestV68ReplyCorrelationUsesRequestAndAskMessageSeparately(t *testing.T) {
	route := store.RelaySealedV1Route{
		Kind: "reply", RequestID: "rq_synthetic", ReplyTo: "msg_ask_synthetic",
	}
	if !v68ReplyCorrelationMatches(route, "rq_synthetic", "msg_ask_synthetic") {
		t.Fatal("exact request and ASK message correlation was rejected")
	}

	wrongReplyTo := route
	wrongReplyTo.ReplyTo = "rq_synthetic"
	if v68ReplyCorrelationMatches(wrongReplyTo, "rq_synthetic", "msg_ask_synthetic") {
		t.Fatal("request ID was incorrectly accepted as the original ASK message ID")
	}

	wrongRequest := route
	wrongRequest.RequestID = "msg_ask_synthetic"
	if v68ReplyCorrelationMatches(wrongRequest, "rq_synthetic", "msg_ask_synthetic") {
		t.Fatal("ASK message ID was incorrectly accepted as the request ID")
	}
}

func TestG2FixtureScenarioFailsBeforePrivateAccess(t *testing.T) {
	for _, value := range []string{"", "g2", "G2-G3", " g1", "g3", "../g2-g3"} {
		if err := validateFixtureScenario(value); err == nil {
			t.Fatal("unknown scenario accepted")
		}
	}
	for _, value := range []string{"g1", "g2-g3"} {
		if err := validateFixtureScenario(value); err != nil {
			t.Fatal(err)
		}
	}
	wire, err := json.Marshal(fixture{Version: 1})
	if err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"scenario", "bob_owner_id", "alice_second_group_id"} {
		if strings.Contains(string(wire), name) {
			t.Fatal("default G1 fixture shape changed")
		}
	}
}

func TestG2BootstrapHasIndependentOwnersAndGroups(t *testing.T) {
	root := t.TempDir()
	if err := os.Chmod(root, 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, ".cicada-v68-owned"), []byte("cicada.v68.disposable.v1\nsynthetic-g2-offline\n"), 0600); err != nil {
		t.Fatal(err)
	}
	db := filepath.Join(root, "hub-state", "hub.db")
	if err := os.Mkdir(filepath.Dir(db), 0700); err != nil {
		t.Fatal(err)
	}
	if err := bootstrap([]string{"--db", db, "--fixture", root, "--scenario", "g2-g3"}); err != nil {
		t.Fatal(err)
	}
	meta, err := readFixture(root)
	if err != nil {
		t.Fatal(err)
	}
	hubWire, err := os.ReadFile(filepath.Join(root, "hub-state", "e2ee", "identity.json"))
	if err != nil {
		t.Fatal(err)
	}
	hubIdentity, err := e2ee.UnmarshalIdentity(hubWire)
	if err != nil || meta.OwnerID == hubIdentity.Public().ID {
		t.Fatal("Alice is incorrectly resident Control owner")
	}
	if meta.Scenario != "g2-g3" || meta.OwnerID == meta.BobOwnerID || meta.GroupID == meta.AliceSecondGroupID || meta.GroupID == meta.BobGroupID || meta.AliceSecondGroupID == meta.BobGroupID {
		t.Fatal("G2 collapsed independent authority")
	}
	s, err := store.New(db)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	for groupID, ownerID := range map[string]string{meta.GroupID: meta.OwnerID, meta.AliceSecondGroupID: meta.OwnerID, meta.BobGroupID: meta.BobOwnerID} {
		group, err := s.GetGroup(groupID)
		if err != nil || group == nil || group.OwnerPrincipalID != ownerID {
			t.Fatal("Group owner mismatch")
		}
	}
	for nodeID, state := range map[string]string{meta.NodeA: meta.SourceState, meta.NodeB: meta.TargetState} {
		crypto, err := nodekeys.OpenCryptoState(filepath.Join(state, "nodes", "node-"+nodeID))
		if err != nil {
			t.Fatal(err)
		}
		for ownerID, keyID := range map[string]string{meta.OwnerID: meta.OwnerKeyID, meta.BobOwnerID: meta.BobOwnerKeyID} {
			trusted, err := crypto.GetNodeOwnerKeyTrustLocal(ownerID, keyID)
			if err != nil || trusted.State != nodekeys.NodeOwnerKeyTrustActive {
				t.Fatal("independent local Owner trust absent")
			}
		}
		if _, err := crypto.GetNodeOwnerKeyTrustLocal("synthetic-untrusted-owner", meta.BobOwnerKeyID); err == nil {
			t.Fatal("foreign owner inferred from matching key")
		}
		crypto.Close()
	}
	for _, thread := range []string{meta.ThreadA, meta.ThreadB} {
		endpoint, err := s.GetEndpointV2BySession("codex", thread)
		if err != nil {
			t.Fatal(err)
		}
		if endpoint != nil {
			t.Fatal("bootstrap fabricated actual Join Endpoint")
		}
	}
	if err := approve([]string{"--db", db, "--fixture", root}); err == nil {
		t.Fatal("Link consent accepted before actual Joins")
	}
}

type fixtureRoundTripper func(*http.Request) (*http.Response, error)

func (f fixtureRoundTripper) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

func TestG3EncryptedSnapshotAndPlaintextDenialWithoutListener(t *testing.T) {
	device, err := e2ee.NewIdentity()
	if err != nil {
		t.Fatal(err)
	}
	hub, err := e2ee.NewIdentity()
	if err != nil {
		t.Fatal(err)
	}
	binding := clientwire.Binding{HubID: "hub_synthetic", OwnerID: "owner_synthetic", DeviceID: "device_synthetic", SessionEpoch: 1, HubKeyVersion: 1, DeviceKeyVersion: 1}
	calls := 0
	client := &http.Client{Transport: fixtureRoundTripper(func(r *http.Request) (*http.Response, error) {
		calls++
		if r.URL.String() != "http://127.0.0.1:8787/v2/client/rpc" || r.Method != http.MethodPost || r.Header.Get("Authorization") != "" {
			t.Fatal("unexpected management route/auth")
		}
		raw, err := io.ReadAll(r.Body)
		if err != nil {
			t.Fatal(err)
		}
		if bytes.Contains(raw, []byte(`"groups"`)) {
			t.Fatal("request contained clear management payload")
		}
		request, err := clientwire.OpenRequest(hub, device.Public(), binding, raw)
		if err != nil || request.Route.Operation != "status.snapshot" || string(request.Plaintext) != "{}" {
			t.Fatal("request was not exact authenticated snapshot")
		}
		route := request.Route
		route.Direction = clientwire.DirectionResponse
		route.SenderKeyID = hub.Public().ID
		route.ReceiverKeyID = device.Public().ID
		route.SenderKeyVersion = 1
		route.ReceiverKeyVersion = 1
		response, err := clientwire.SealResponse(hub, device.Public(), binding, route, []byte(`{"ok":true,"result":{"owner_principal_id":"owner_synthetic"}}`))
		if err != nil {
			t.Fatal(err)
		}
		return &http.Response{StatusCode: 200, Body: io.NopCloser(bytes.NewReader(response)), Header: make(http.Header)}, nil
	})}
	plain, err := queryControlSnapshot(client, "http://127.0.0.1:8787", device, hub.Public(), binding, 1)
	if err != nil || !bytes.Contains(plain, []byte("owner_synthetic")) || calls != 1 {
		t.Fatal("encrypted snapshot failed")
	}
	if _, err := queryControlSnapshot(client, "http://127.0.0.1:8788", device, hub.Public(), binding, 2); err == nil || calls != 1 {
		t.Fatal("foreign origin reached transport")
	}
	wrong, err := e2ee.NewIdentity()
	if err != nil {
		t.Fatal(err)
	}
	client.Transport = fixtureRoundTripper(func(r *http.Request) (*http.Response, error) {
		return &http.Response{StatusCode: 200, Body: io.NopCloser(bytes.NewReader([]byte(`{"ok":true}`)))}, nil
	})
	if _, err := queryControlSnapshot(client, "http://127.0.0.1:8787", device, wrong.Public(), binding, 2); err == nil {
		t.Fatal("plaintext capabilities accepted as encrypted snapshot")
	}
}

func TestG3TypedSnapshotRequiresOriginalMembershipAndOwnerVisibility(t *testing.T) {
	meta := fixture{OwnerID: "alice", GroupID: "left", AliceSecondGroupID: "survives", BobGroupID: "hidden", ThreadA: "original-a", ThreadB: "original-b", NodeA: "node-a", NodeB: "node-b"}
	valid := `{"ok":true,"result":{"owner_principal_id":"alice","groups":[{"group_id":"left"},{"group_id":"survives"}],"endpoints":[{"endpoint_id":"exact-a","native_session_id":"original-a","group_ids":["survives"]}],"nodes":[{"node_id":"node-a"}]}}`
	if err := validateG3Snapshot([]byte(valid), meta, "exact-a"); err != nil {
		t.Fatal(err)
	}
	for name, bad := range map[string]string{"foreignowner": strings.Replace(valid, `"alice"`, `"bob"`, 1), "leftmembership": strings.Replace(valid, `"group_ids":["survives"]`, `"group_ids":["left","survives"]`, 1), "foreignendpoint": strings.Replace(valid, "original-a", "original-b", 1), "foreigngroup": strings.Replace(valid, `{"group_id":"left"}`, `{"group_id":"hidden"}`, 1), "missingnode": strings.Replace(valid, "node-a", "unknown", 1)} {
		t.Run(name, func(t *testing.T) {
			if err := validateG3Snapshot([]byte(bad), meta, "exact-a"); err == nil {
				t.Fatal("bad scoped snapshot accepted")
			}
		})
	}
}

func TestTLSBootstrapRequiresPinnedImplementationRegistration(t *testing.T) {
	saved := nativeTLSBootstrap
	nativeTLSBootstrap = nil
	defer func() { nativeTLSBootstrap = saved }()
	if err := dispatchTLSBootstrap([]string{"synthetic"}); err == nil {
		t.Fatal("missing implementation accepted")
	}
	calls := 0
	nativeTLSBootstrap = func(raw []string) error {
		calls++
		if len(raw) != 1 || raw[0] != "synthetic" {
			t.Fatal("dispatch changed arguments")
		}
		return nil
	}
	if err := dispatchTLSBootstrap([]string{"synthetic"}); err != nil || calls != 1 {
		t.Fatal("registered exact implementation not dispatched")
	}
}

func TestG1BootstrapDefaultAndUnknownScenarioBeforeFixtureAccess(t *testing.T) {
	if err := bootstrap([]string{"--db", "/synthetic-missing/db", "--fixture", "/synthetic-missing", "--scenario", "unknown"}); err == nil || err.Error() != "unsupported fixture scenario" {
		t.Fatal("unknown scenario reached fixture validation")
	}
	root := t.TempDir()
	if err := os.Chmod(root, 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, ".cicada-v68-owned"), []byte("cicada.v68.disposable.v1\nsynthetic-g1-offline\n"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(filepath.Join(root, "hub-state"), 0700); err != nil {
		t.Fatal(err)
	}
	if err := bootstrap([]string{"--db", filepath.Join(root, "hub-state", "hub.db"), "--fixture", root}); err != nil {
		t.Fatal(err)
	}
	wire, err := os.ReadFile(filepath.Join(root, "fixture.json"))
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(wire), `"scenario"`) || strings.Contains(string(wire), `"bob_owner_id"`) {
		t.Fatal("default fixture metadata changed")
	}
	meta, err := readFixture(root)
	if err != nil || meta.Scenario != "" || meta.BobOwnerID != "" {
		t.Fatal("default G1 topology changed")
	}
}

func TestG2SecondMembershipRequiresRealFirstJoin(t *testing.T) {
	root := t.TempDir()
	if err := os.Chmod(root, 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, ".cicada-v68-owned"), []byte("cicada.v68.disposable.v1\nsynthetic-g2-membership\n"), 0600); err != nil {
		t.Fatal(err)
	}
	db := filepath.Join(root, "hub-state", "hub.db")
	if err := os.Mkdir(filepath.Dir(db), 0700); err != nil {
		t.Fatal(err)
	}
	argv := []string{"--db", db, "--fixture", root}
	if err := bootstrap(append(append([]string{}, argv...), "--scenario", "g2-g3")); err != nil {
		t.Fatal(err)
	}
	if err := authorizeG2Second(argv); err == nil {
		t.Fatal("authorization without real Join")
	}
	meta, err := readFixture(root)
	if err != nil {
		t.Fatal(err)
	}
	s, err := store.New(db)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	token, err := os.ReadFile(filepath.Join(meta.SourceState, "nodes", "node-"+meta.NodeA, "relay.token"))
	if err != nil {
		t.Fatal(err)
	}
	service, err := fabric.NewService(s, meta.OwnerID, meta.OwnerID)
	if err != nil {
		t.Fatal(err)
	}
	first, err := service.JoinForNodeCredential(strings.TrimSpace(string(token)), fabric.JoinInput{GroupID: meta.GroupID, Harness: "codex", NativeSessionID: meta.ThreadA, Workspace: "/synthetic"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := service.JoinForNodeCredential(strings.TrimSpace(string(token)), fabric.JoinInput{GroupID: meta.AliceSecondGroupID, Harness: "codex", NativeSessionID: meta.ThreadA, Workspace: "/synthetic"}); err == nil {
		t.Fatal("unapproved second Join")
	}
	principal, err := s.GetPrincipal(first.Endpoint.PrincipalID)
	if err != nil {
		t.Fatal(err)
	}
	binding, err := s.GetActiveSessionBinding(first.Endpoint.ID)
	if err != nil {
		t.Fatal(err)
	}
	group, err := s.GetGroup(meta.AliceSecondGroupID)
	if err != nil {
		t.Fatal(err)
	}
	for _, field := range []string{"owner", "principal", "sid", "node", "binding", "binding-id", "binding-status", "expired-lease", "group", "group-owner"} {
		t.Run(field, func(t *testing.T) {
			ep, p, b, g := first.Endpoint, *principal, *binding, *group
			switch field {
			case "owner":
				ep.Owner = meta.BobOwnerID
			case "principal":
				ep.PrincipalID = "foreign"
			case "sid":
				ep.NativeSessionID = "foreign"
			case "node":
				ep.MachineID = meta.NodeB
			case "binding":
				b.Epoch = 0
			case "binding-id":
				b.ID = "foreign"
			case "binding-status":
				b.Status = "revoked"
			case "expired-lease":
				b.LeaseExpiresAt = time.Now().UTC().Add(-time.Second).Format(time.RFC3339Nano)
			case "group":
				g.ID = meta.GroupID
			case "group-owner":
				g.OwnerPrincipalID = meta.BobOwnerID
			}
			if validateG2SecondAuthority(meta, &ep, &p, &b, &g) == nil {
				t.Fatal("foreign authority accepted")
			}
		})
	}
	if err := authorizeG2Second(argv); err != nil {
		t.Fatal(err)
	}
	membership, err := s.GetMembershipByPrincipalGroup(principal.ID, group.ID)
	if err != nil || membership.Role != "member" || strings.Join(membership.Roles, ",") != "member" || strings.Join(membership.Grants, ",") != "directory.read,message.send,message.ask,message.reply,message.receive" {
		t.Fatal("second membership grants or roles widened")
	}
	if group.ContextPolicy != "group_scoped" || group.NetworkID != "" {
		t.Fatal("fixture no longer uses explicit same-Owner group_scoped shared context policy")
	}
	second, err := service.JoinForNodeCredential(strings.TrimSpace(string(token)), fabric.JoinInput{GroupID: meta.AliceSecondGroupID, Harness: "codex", NativeSessionID: meta.ThreadA, Workspace: "/synthetic"})
	if err != nil {
		t.Fatal(err)
	}
	if first.NativeContextScope.GroupContextPolicy != "group_scoped" || second.NativeContextScope.GroupContextPolicy != "group_scoped" {
		t.Fatal("Join did not expose explicit Owner context policy")
	}
	if second.Endpoint.ID != first.Endpoint.ID || second.Endpoint.PrincipalID != first.Endpoint.PrincipalID || second.Endpoint.NativeSessionID != meta.ThreadA {
		t.Fatal("second Join replaced original identity")
	}
	if err := authorizeG2Second(argv); err == nil {
		t.Fatal("authorization repeated after binding changed")
	}
}
