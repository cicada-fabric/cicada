package main

// This helper seeds and observes disposable fixtures only. Hub and Agent run
// the exact production binary extracted from the reviewed clean Hub image.
import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/http/httputil"
	"net/url"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/cicada-ai/cicada/internal/clientwire"
	"github.com/cicada-ai/cicada/internal/e2ee"
	"github.com/cicada-ai/cicada/internal/fabric"
	"github.com/cicada-ai/cicada/internal/nodeinbox"
	"github.com/cicada-ai/cicada/internal/nodekeys"
	"github.com/cicada-ai/cicada/internal/store"
)

type multiHubDockerEntry struct {
	Name              string `json:"name"`
	NetworkID         string `json:"network_id"`
	HubID             string `json:"hub_id"`
	OwnerID           string `json:"owner_id"`
	NodeID            string `json:"node_id"`
	Target            string `json:"target"`
	Origin            string `json:"origin"`
	StateRelative     string `json:"state_relative"`
	Token             string `json:"token"`
	ForeignOwnerToken string `json:"foreign_owner_token"`
	ManagerToken      string `json:"manager_token"`
}

type multiHubDockerMetric struct {
	Heartbeats            int `json:"heartbeats_ok"`
	NetworkClaims         int `json:"network_claims_ok"`
	LostResponses         int `json:"fixture_lost_responses"`
	NetworkNonempty       int `json:"network_nonempty_deliveries"`
	NetworkAuthorizations int `json:"network_authorizations_ok"`
	NodeReceived          int `json:"network_receipts_ok"`
	Claims                int `json:"sealed_claims_ok"`
	GroupClaims           int `json:"group_claims_ok"`
	SSEHeaders            int `json:"sse_headers_ok"`
	SSEReady              int `json:"sse_ready_frames"`
	WrongAgentBearer      int `json:"wrong_agent_bearer"`
	ControlRequests       int `json:"control_requests"`
	UpstreamFailures      int `json:"upstream_failures"`
}

func multiHubDockerPrivateRoot(root string) error {
	if !filepath.IsAbs(root) || filepath.Clean(root) != root {
		return errors.New("absolute private owned root required")
	}
	st, err := os.Lstat(root)
	if err != nil || st.Mode() != os.ModeDir|0700 {
		return errors.New("real private root required")
	}
	st, err = os.Lstat(filepath.Join(root, ".multi-hub-owned"))
	if err != nil || st.Mode() != 0600 {
		return errors.New("private fixture ownership marker required")
	}
	b, err := os.ReadFile(filepath.Join(root, ".multi-hub-owned"))
	if err != nil || !strings.HasPrefix(string(b), "cicada.multihub.disposable.v1\n") {
		return errors.New("fixture ownership marker invalid")
	}
	return nil
}

func multiHubDockerWrite(path string, value any) error {
	b, err := json.Marshal(value)
	if err != nil {
		return err
	}
	return os.WriteFile(path, append(b, '\n'), 0600)
}

// Synthetic bootstrap creates keys, invitations and approved disposable Nodes.
// Endpoint enrollment, key consent and all Relay writes happen later through HTTP.
func multiHubDockerSeed(root string) error {
	if err := multiHubDockerPrivateRoot(root); err != nil {
		return err
	}
	if _, err := os.Lstat(filepath.Join(root, "node")); !errors.Is(err, os.ErrNotExist) {
		return errors.New("refuse existing fixture state")
	}
	marker, err := os.ReadFile(filepath.Join(root, ".multi-hub-owned"))
	if err != nil {
		return err
	}
	configs := map[string][]machineHubConfig{"node": {}, "node-r": {}}
	entries := map[string][]multiHubDockerEntry{"node": {}, "node-r": {}}
	public := []map[string]string{}
	for _, n := range []string{"node", "node-r"} {
		wr := filepath.Join(root, n, "state")
		if err = os.MkdirAll(wr, 0700); err != nil {
			return err
		}
		if err = os.WriteFile(filepath.Join(root, n, ".multi-hub-owned"), marker, 0600); err != nil {
			return err
		}
		admissions, e := nodeinbox.OpenProviderAdmissionLedger(filepath.Join(wr, "node-provider-admission.sqlite3"))
		if e != nil {
			return e
		}
		if e = admissions.Close(); e != nil {
			return e
		}
		contexts, e := nodeinbox.OpenNativeContextRegistry(filepath.Join(wr, "node-native-context-history.sqlite3"))
		if e != nil {
			return e
		}
		if e = contexts.Close(); e != nil {
			return e
		}
	}
	for index, name := range []string{"a", "b"} {
		state := filepath.Join(root, "hubs", name, "state")
		operator := filepath.Join(root, "operator", name)
		for _, dir := range []string{filepath.Join(state, "e2ee"), filepath.Join(root, "hubs", name, "workspace"), operator} {
			if err = os.MkdirAll(dir, 0700); err != nil {
				return err
			}
		}
		keys := map[string]*e2ee.Identity{}
		for _, label := range []string{"hub", "control", "owner", "device", "foreign-owner", "foreign-device"} {
			keys[label], err = e2ee.NewIdentity()
			if err != nil {
				return err
			}
		}
		for path, key := range map[string]*e2ee.Identity{filepath.Join(state, "e2ee/identity.json"): keys["hub"], filepath.Join(state, "e2ee/client-control-identity.json"): keys["control"], filepath.Join(operator, "owner.key"): keys["owner"], filepath.Join(operator, "device.key"): keys["device"]} {
			wire, e := key.MarshalBinary()
			if e != nil {
				return e
			}
			if err = os.WriteFile(path, wire, 0600); err != nil {
				return err
			}
		}
		db, e := store.New(filepath.Join(state, "cicada.sqlite3"))
		if e != nil {
			return e
		}
		// Close also on errors; no acceptance rows or peer payload are fabricated.
		err = func() error {
			defer db.Close()
			hubID, e := db.GetClientHubID()
			if e != nil {
				return e
			}
			ownerID := keys["hub"].Public().ID
			deviceID := "synthetic_multihub_device_" + name
			for _, foreign := range []bool{false, true} {
				own, dev, id, did := keys["owner"], keys["device"], ownerID, deviceID
				if foreign {
					own, dev, id, did = keys["foreign-owner"], keys["foreign-device"], keys["foreign-owner"].Public().ID, deviceID+"_foreign"
				}
				if _, e = db.CreatePrincipal(store.Principal{ID: id, Kind: store.PrincipalKindHuman, OwnerID: id, TrustDomainID: id, Name: "Synthetic disposable Owner", Status: store.PrincipalStatusActive}); e != nil {
					return e
				}
				if _, e = db.RegisterOwnerApprovalKeyLocal(id, own.Public()); e != nil {
					return e
				}
				grant, e := own.SignOwnerDeviceGrant(id, did, dev.Public(), hubID, e2ee.OwnerDevicePurposeControl, time.Now().Add(-time.Minute), time.Now().Add(time.Hour))
				if e != nil {
					return e
				}
				if _, e = db.RegisterClientDeviceFromOwnerGrant(store.RegisterClientDeviceInput{OwnerID: id, OwnerKeyID: own.Public().ID, DeviceID: did, DevicePublic: dev.Public(), OwnerDeviceGrant: grant}); e != nil {
					return e
				}
			}
			netID := "net_multihub_synthetic"
			if _, e = db.CreateNetwork(store.Network{ID: netID, HubID: hubID, OwnerID: ownerID, Name: "Synthetic isolated multi-Hub Network"}); e != nil {
				return e
			}
			if e = db.ActivateNetworkMode(); e != nil {
				return e
			}
			foreignToken := ""
			nodeTokens := map[string]string{}
			for _, n := range []string{"node_foreign_owner_" + name, "node_multihub_sender", "node_multihub_receiver"} {
				id, did := ownerID, deviceID
				if strings.HasPrefix(n, "node_foreign") {
					id, did = keys["foreign-owner"].Public().ID, deviceID+"_foreign"
				}
				token, digest, e := fabric.NewNodeCredential()
				if e != nil {
					return e
				}
				code := sha256.Sum256([]byte("synthetic-multihub-bind\x00" + name + "\x00" + n))
				codeDigest := hex.EncodeToString(code[:])
				if _, e = db.CreatePendingNodeDeviceBinding(n, "Synthetic Node", digest, codeDigest, time.Now().Add(10*time.Minute)); e != nil {
					return e
				}
				if _, e = db.ConfirmPendingNodeDeviceBinding(id, did, codeDigest); e != nil {
					return e
				}
				if strings.HasPrefix(n, "node_foreign") {
					foreignToken = token
				} else {
					nodeTokens[n] = token
				}
			}
			var secret [32]byte
			if _, e = rand.Read(secret[:]); e != nil {
				return e
			}
			manager := "synthetic-" + hex.EncodeToString(secret[:])
			if e = os.WriteFile(filepath.Join(root, "hubs", name, "env"), []byte("CICADA_API_TOKEN="+manager+"\n"), 0600); e != nil {
				return e
			}
			meta := multiHubDockerOperator{HubID: hubID, NetworkID: netID, OwnerID: ownerID, DeviceID: deviceID, HubPublic: keys["control"].Public()}
			grants := []string{"directory.discover", "directory.publish", "direct.receive", "direct.send"}
			for i, n := range []string{"node", "node-r"} {
				nodeID := []string{"node_multihub_sender", "node_multihub_receiver"}[i]
				config := machineHubConfig{HubID: hubID, ControlURL: fmt.Sprintf("http://127.0.0.1:%d", 18871+index), NodeID: nodeID, Name: "synthetic multi-Hub " + name}
				hubState := machineHubStateDir(filepath.Join(root, n, "state"), config)
				token := nodeTokens[nodeID]
				if e = persistMachineNodeIdentity(filepath.Join(machineNodeStateDir(hubState, nodeID), "identity.json"), machineNodeCredentialPath(hubState, nodeID), &machineNodeIdentity{Version: 1, NodeID: nodeID, RelayToken: token}); e != nil {
					return e
				}
				crypto, e := nodekeys.OpenCryptoState(machineNodeStateDir(hubState, nodeID))
				if e != nil {
					return e
				}
				fp, e := nodekeys.PeerKeyFingerprint(keys["owner"].Public())
				if e == nil {
					_, e = crypto.TrustOwnerApprovalKeyLocal(ownerID, keys["owner"].Public().ID, keys["owner"].Public(), fp)
				}
				closeErr := crypto.Close()
				if e != nil {
					return e
				}
				if closeErr != nil {
					return closeErr
				}
				relative := strings.TrimPrefix(hubState, filepath.Join(root, n)+string(filepath.Separator))
				entry := multiHubDockerEntry{Name: name, HubID: hubID, NetworkID: netID, OwnerID: ownerID, NodeID: nodeID, Target: "http://hub-" + name + ":8787", Origin: config.ControlURL, StateRelative: relative, Token: token, ForeignOwnerToken: foreignToken, ManagerToken: manager}
				entries[n] = append(entries[n], entry)
				configs[n] = append(configs[n], config)
				invitation, _, e := fabric.NewSessionCredential()
				if e != nil {
					return e
				}
				expiry := time.Now().UTC().Add(time.Hour)
				if e = db.IssueNetworkInvitation(netID, ownerID, ownerID, invitation, expiry.Format(time.RFC3339Nano), grants); e != nil {
					return e
				}
				native := "synthetic-multihub-session-" + n
				proof, e := keys["owner"].SignOwnerNetworkJoinGrant(ownerID, hubID, netID, nodeID, native, store.NetworkInvitationDigest(invitation), keys["owner"].Public().ID, grants, true, time.Now().UTC().Add(-time.Minute), expiry)
				if e != nil {
					return e
				}
				meta.Joins = append(meta.Joins, fabric.NetworkJoinInput{NetworkID: netID, InvitationToken: invitation, OwnerJoinProof: string(proof), Harness: "codex", NativeSessionID: native, EndpointName: "synthetic-" + n, LeaseSeconds: 3600})
			}
			if e = multiHubDockerWrite(filepath.Join(operator, "metadata.json"), meta); e != nil {
				return e
			}
			public = append(public, map[string]string{"name": name, "hub_id": hubID, "network_id": netID, "owner_id": ownerID, "node_id": "node_multihub_sender", "receiver_node_id": "node_multihub_receiver", "origin": entries["node"][index].Origin, "state_relative": entries["node"][index].StateRelative, "receiver_state_relative": entries["node-r"][index].StateRelative})
			return nil
		}()
		if err != nil {
			return err
		}
	}
	for _, n := range []string{"node", "node-r"} {
		if err = multiHubDockerWrite(filepath.Join(root, n, "proxy.json"), entries[n]); err != nil {
			return err
		}
		if err = multiHubDockerWrite(filepath.Join(root, n, "hubs.json"), machineHubConfigFile{Version: 1, Hubs: configs[n]}); err != nil {
			return err
		}
	}
	return multiHubDockerWrite(filepath.Join(root, "fixture-public.json"), public)
}

type multiHubDockerOperator struct {
	HubID          string                             `json:"hub_id"`
	NetworkID      string                             `json:"network_id"`
	OwnerID        string                             `json:"owner_id"`
	DeviceID       string                             `json:"device_id"`
	HubPublic      e2ee.PublicIdentity                `json:"hub_public"`
	Joins          []fabric.NetworkJoinInput          `json:"joins"`
	Registered     []fabric.NetworkJoinResult         `json:"registered,omitempty"`
	NativeBindings []store.NetworkDirectNativeBinding `json:"native_bindings,omitempty"`
	Sequence       uint64                             `json:"sequence"`
}

func multiHubDockerLoad(root string) ([]multiHubDockerEntry, error) {
	if err := multiHubDockerPrivateRoot(root); err != nil {
		return nil, err
	}
	st, err := os.Lstat(filepath.Join(root, "proxy.json"))
	if err != nil || st.Mode() != 0600 || st.Size() > 16384 {
		return nil, errors.New("private bounded fixture config required")
	}
	b, err := os.ReadFile(filepath.Join(root, "proxy.json"))
	if err != nil {
		return nil, err
	}
	var entries []multiHubDockerEntry
	if err = json.Unmarshal(b, &entries); err != nil {
		return nil, err
	}
	if len(entries) != 2 || entries[0].HubID == entries[1].HubID || entries[0].Token == entries[1].Token || entries[0].OwnerID == entries[1].OwnerID {
		return nil, errors.New("independent Hub coordinates required")
	}
	for i, e := range entries {
		if e.Name != []string{"a", "b"}[i] || e.Target != "http://hub-"+e.Name+":8787" || e.Origin != fmt.Sprintf("http://127.0.0.1:%d", 18871+i) || e.Token == "" || e.ForeignOwnerToken == "" || e.ManagerToken == "" {
			return nil, errors.New("fixture config coordinates invalid")
		}
	}
	return entries, nil
}

type multiHubDockerObservedBody struct {
	io.ReadCloser
	prefix []byte
	mark   func()
	done   bool
}

func (b *multiHubDockerObservedBody) Read(p []byte) (int, error) {
	n, err := b.ReadCloser.Read(p)
	if !b.done {
		want := []byte("event: ready\ndata: claim\n\n")
		take := len(want) - len(b.prefix)
		if take > n {
			take = n
		}
		b.prefix = append(b.prefix, p[:take]...)
		if len(b.prefix) == len(want) {
			b.done = true
			if bytes.Equal(b.prefix, want) {
				b.mark()
			}
			b.prefix = nil
		}
	}
	return n, err
}

func multiHubDockerRuntime(root string) error {
	entries, err := multiHubDockerLoad(root)
	if err != nil {
		return err
	}
	var mu sync.Mutex
	metrics := map[string]*multiHubDockerMetric{"a": {}, "b": {}}
	update := func(name string, f func(*multiHubDockerMetric)) {
		mu.Lock()
		defer mu.Unlock()
		f(metrics[name])
		tmp := filepath.Join(root, "observed.tmp")
		if e := multiHubDockerWrite(tmp, metrics); e == nil {
			_ = os.Rename(tmp, filepath.Join(root, "observed.json"))
		}
	}
	servers := []*http.Server{}
	for _, entry := range entries {
		e := entry
		target, _ := url.Parse(e.Target)
		proxy := httputil.NewSingleHostReverseProxy(target)
		proxy.Transport = &http.Transport{Proxy: nil}
		proxy.FlushInterval = -1
		proxy.ErrorHandler = func(w http.ResponseWriter, r *http.Request, err error) {
			update(e.Name, func(m *multiHubDockerMetric) { m.UpstreamFailures++ })
			http.Error(w, "fixture upstream unavailable", 502)
		}
		proxy.ModifyResponse = func(resp *http.Response) error {
			r := resp.Request
			probe := r.Header.Get("X-Cicada-Fixture-Probe") == "1"
			if probe {
				if r.Header.Get("X-Cicada-Fixture-Lose-Reply") == "1" && r.URL.Path == "/v2/fabric/node/networks/direct/send" && resp.StatusCode == 202 {
					update(e.Name, func(m *multiHubDockerMetric) { m.LostResponses++ })
					return errors.New("synthetic loss after actual Hub 202 acceptance")
				}
				return nil
			}
			deliveries := 0
			if r.URL.Path == "/v2/fabric/node/networks/direct/claim" && resp.StatusCode == 200 {
				body, err := io.ReadAll(io.LimitReader(resp.Body, 4*1024*1024+1))
				_ = resp.Body.Close()
				if err != nil || len(body) > 4*1024*1024 {
					return errors.New("bounded observer claim response required")
				}
				var result struct {
					Deliveries []json.RawMessage `json:"deliveries"`
				}
				if err = json.Unmarshal(body, &result); err != nil {
					return errors.New("observer expected production claim DTO")
				}
				deliveries = len(result.Deliveries)
				resp.Body = io.NopCloser(bytes.NewReader(body))
			}
			update(e.Name, func(m *multiHubDockerMetric) {
				if resp.StatusCode == 200 {
					switch r.URL.Path {
					case "/v2/fabric/node/networks/direct/claim":
						m.NetworkClaims++
						m.NetworkNonempty += deliveries
					case "/v2/fabric/node/networks/direct/authorize":
						m.NetworkAuthorizations++
					case "/v2/fabric/node/networks/direct/receipt":
						m.NodeReceived++
					}
				}
				if strings.HasPrefix(r.URL.Path, "/v1/") {
					m.ControlRequests++
				}
				if strings.HasPrefix(r.URL.Path, "/v2/") && r.Header.Get("Authorization") != "CicadaNode "+e.Token {
					m.WrongAgentBearer++
				}
				prefix := "/v2/relay/nodes/" + e.NodeID
				switch r.URL.Path {
				case prefix + "/heartbeat":
					if resp.StatusCode == 204 {
						m.Heartbeats++
					}
				case prefix + "/sealed/claim":
					if resp.StatusCode == 200 {
						m.Claims++
					}
				case prefix + "/group/sealed/claim":
					if resp.StatusCode == 200 {
						m.GroupClaims++
					}
				case prefix + "/events":
					if resp.StatusCode == 200 && resp.Header.Get("Content-Type") == "text/event-stream" {
						m.SSEHeaders++
					}
				}
			})
			if strings.HasSuffix(r.URL.Path, "/events") && resp.StatusCode == 200 {
				resp.Body = &multiHubDockerObservedBody{ReadCloser: resp.Body, mark: func() { update(e.Name, func(m *multiHubDockerMetric) { m.SSEReady++ }) }}
			}
			return nil
		}
		u, _ := url.Parse(e.Origin)
		_, port, err := net.SplitHostPort(u.Host)
		if err != nil {
			return err
		}
		// The Agent origin remains loopback. This test-only observer also accepts
		// owned fixture probes on the unpublished internal Docker interface.
		server := &http.Server{Addr: net.JoinHostPort("0.0.0.0", port), Handler: proxy, ReadHeaderTimeout: 5 * time.Second}
		servers = append(servers, server)
		go func() { _ = server.ListenAndServe() }()
	}
	ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGTERM, syscall.SIGINT)
	defer cancel()
	binary := os.Getenv("CICADA_MULTI_HUB_SHIPPED_BINARY")
	if binary != "/bin-fixture/cicada" {
		return errors.New("exact shipped fixture binary required")
	}
	cmd := exec.Command(binary, "machine", "agent", "--hubs-file", filepath.Join(root, "hubs.json"), "--state-root", filepath.Join(root, "state"), "--relay-only", "--interval", "1s")
	cmd.Env = append(os.Environ(), "CICADA_NODE_TOKEN=synthetic-stale-global-token", "CICADA_HUB_ID=synthetic-stale-global-hub")
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	if err = cmd.Start(); err != nil {
		return err
	}
	done := make(chan error, 1)
	go func() { done <- cmd.Wait() }()
	select {
	case err = <-done:
		return fmt.Errorf("production Agent stopped: %w", err)
	case <-ctx.Done():
	}
	_ = cmd.Process.Signal(syscall.SIGTERM)
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		_ = cmd.Process.Kill()
		<-done
	}
	for _, server := range servers {
		shutdown, cancel := context.WithTimeout(context.Background(), time.Second)
		_ = server.Shutdown(shutdown)
		cancel()
	}
	return nil
}

func multiHubDockerProbe(root string) error {
	entries, err := multiHubDockerLoad(root)
	if err != nil {
		return err
	}
	client := &http.Client{Timeout: 5 * time.Second, Transport: &http.Transport{Proxy: nil}}
	results := []map[string]any{}
	for index, e := range entries {
		for _, test := range []struct {
			name, auth, path string
			want             int
		}{
			{"foreign_hub_bearer", "CicadaNode " + entries[1-index].Token, e.NodeID, 401},
			{"foreign_owner_node_scope", "CicadaNode " + e.ForeignOwnerToken, e.NodeID, 403},
			{"wrong_node_path", "CicadaNode " + e.Token, "node_not_bound", 403},
			{"manager_bearer_cannot_be_node", "Bearer " + e.ManagerToken, e.NodeID, 401},
		} {
			request, _ := http.NewRequest(http.MethodPost, e.Origin+"/v2/relay/nodes/"+test.path+"/heartbeat", strings.NewReader(`{}`))
			request.Header.Set("Authorization", test.auth)
			request.Header.Set("Content-Type", "application/json")
			request.Header.Set("X-Cicada-Fixture-Probe", "1")
			response, makeErr := client.Do(request)
			if makeErr != nil {
				return errors.New("fixture HTTP probe unavailable")
			}
			_, _ = io.Copy(io.Discard, io.LimitReader(response.Body, 4096))
			_ = response.Body.Close()
			if response.StatusCode != test.want {
				return fmt.Errorf("%s Hub %s returned status %d, wanted %d", e.Name, test.name, response.StatusCode, test.want)
			}
			results = append(results, map[string]any{"hub": e.Name, "case": test.name, "status": response.StatusCode, "expected": test.want})
		}
	}
	return json.NewEncoder(os.Stdout).Encode(map[string]any{"cases": results, "result": "PASS"})
}

// Only this test helper possesses synthetic Owner/device material. It sends
// existing production wire packets; Hub and Node acceptance are never seeded.
func multiHubDockerReadPrivate(path string, value any) error {
	st, err := os.Lstat(path)
	if err != nil || st.Mode() != 0600 || st.Size() > 256*1024 {
		return errors.New("bounded private fixture file required")
	}
	b, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	return json.Unmarshal(b, value)
}
func multiHubDockerSigner(path string) (*e2ee.Identity, error) {
	st, err := os.Lstat(path)
	if err != nil || st.Mode() != 0600 || st.Size() > 65536 {
		return nil, errors.New("private synthetic signer required")
	}
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	return e2ee.UnmarshalIdentity(b)
}
func multiHubDockerHTTP(base, path, auth string, input, out any, want int) error {
	body, err := json.Marshal(input)
	if err != nil {
		return err
	}
	req, err := http.NewRequest(http.MethodPost, base+path, bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	if auth != "" {
		req.Header.Set("Authorization", auth)
	}
	req.Header.Set("X-Cicada-Fixture-Probe", "1")
	client := &http.Client{Timeout: 10 * time.Second, Transport: &http.Transport{Proxy: nil}}
	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("fixture production HTTP unavailable: %s", path)
	}
	defer resp.Body.Close()
	data, err := io.ReadAll(io.LimitReader(resp.Body, 256*1024+1))
	if err != nil || len(data) > 256*1024 {
		return errors.New("bounded production response required")
	}
	if resp.StatusCode != want {
		return fmt.Errorf("production %s HTTP status %d wanted %d", path, resp.StatusCode, want)
	}
	if want >= 400 {
		var denied struct {
			Error string `json:"error"`
		}
		if json.Unmarshal(data, &denied) != nil || denied.Error == "" {
			return errors.New("typed production denial required")
		}
		return nil
	}
	if out != nil {
		return json.Unmarshal(data, out)
	}
	return nil
}
func multiHubDockerControlRPC(root string, e multiHubDockerEntry, m *multiHubDockerOperator, operation string, input, out any) error {
	if operation != "network.key_manifest" && operation != "network.key_grant" {
		return errors.New("fixture Control operation not allowlisted")
	}
	dir := filepath.Join(root, "operator", e.Name)
	device, err := multiHubDockerSigner(filepath.Join(dir, "device.key"))
	if err != nil {
		return err
	}
	m.Sequence++
	if err = multiHubDockerWrite(filepath.Join(dir, "metadata.json"), m); err != nil {
		return err
	}
	body, err := json.Marshal(input)
	if err != nil {
		return err
	}
	binding := clientwire.Binding{HubID: m.HubID, OwnerID: m.OwnerID, DeviceID: m.DeviceID, SessionEpoch: 1, HubKeyVersion: 1, DeviceKeyVersion: 1}
	route := clientwire.Route{Version: 1, Direction: clientwire.DirectionRequest, HubID: m.HubID, OwnerID: m.OwnerID, DeviceID: m.DeviceID, SessionEpoch: 1, Sequence: m.Sequence, OperationID: fmt.Sprintf("synthetic-multihub-control-%d", m.Sequence), Operation: operation, SenderKeyID: device.Public().ID, SenderKeyVersion: 1, ReceiverKeyID: m.HubPublic.ID, ReceiverKeyVersion: 1}
	packet, err := clientwire.SealRequest(device, m.HubPublic, binding, route, body)
	if err != nil {
		return err
	}
	req, err := http.NewRequest(http.MethodPost, e.Target+"/v2/client/rpc", bytes.NewReader(packet))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	client := &http.Client{Timeout: 10 * time.Second, Transport: &http.Transport{Proxy: nil}}
	resp, err := client.Do(req)
	if err != nil {
		return errors.New("encrypted synthetic Control unavailable")
	}
	defer resp.Body.Close()
	wire, err := io.ReadAll(io.LimitReader(resp.Body, 256*1024+1))
	if err != nil || len(wire) > 256*1024 {
		return errors.New("bounded encrypted Control response required")
	}
	if resp.StatusCode != 200 {
		var denied struct {
			Error string `json:"error"`
		}
		if json.Unmarshal(wire, &denied) != nil || denied.Error == "" {
			return errors.New("typed encrypted Control refusal required")
		}
		return fmt.Errorf("encrypted Control status %d", resp.StatusCode)
	}
	opened, err := clientwire.OpenResponse(device, m.HubPublic, binding, wire)
	if err != nil {
		return err
	}
	var reply struct {
		OperationID string          `json:"operation_id"`
		OK          bool            `json:"ok"`
		Result      json.RawMessage `json:"result"`
	}
	if json.Unmarshal(opened.Plaintext, &reply) != nil || !reply.OK || reply.OperationID != route.OperationID {
		return errors.New("encrypted Control operation rejected or miscorrelated")
	}
	if out != nil {
		return json.Unmarshal(reply.Result, out)
	}
	return nil
}
func multiHubDockerControlAbsent(root string) error {
	if err := multiHubDockerPrivateRoot(root); err != nil {
		return err
	}
	entries, err := multiHubDockerLoad(filepath.Join(root, "node"))
	if err != nil {
		return err
	}
	result := []map[string]any{}
	for _, e := range entries {
		client := &http.Client{Timeout: time.Second, Transport: &http.Transport{Proxy: nil}}
		ready := false
		deadline := time.Now().Add(20 * time.Second)
		for time.Now().Before(deadline) {
			resp, err := client.Get(e.Target + "/healthz")
			if err == nil {
				resp.Body.Close()
				if resp.StatusCode == 200 {
					ready = true
					break
				}
			}
			time.Sleep(200 * time.Millisecond)
		}
		if !ready {
			return errors.New("Control-absent peer Hub readiness failed")
		}
		var meta multiHubDockerOperator
		if err = multiHubDockerReadPrivate(filepath.Join(root, "operator", e.Name, "metadata.json"), &meta); err != nil {
			return err
		}
		if len(meta.Registered) != 2 {
			return errors.New("actual enrollment before Control removal required")
		}
		before, err := multiHubDockerBusinessRows(root, e.Name)
		if err != nil {
			return err
		}
		err = multiHubDockerControlRPC(root, e, &meta, "network.key_manifest", map[string]string{"network_id": e.NetworkID, "endpoint_id": meta.Registered[0].Endpoint.ID}, nil)
		if err == nil || err.Error() != "encrypted Control status 503" {
			return errors.New("Control-absent Hub failed typed Control503 boundary")
		}
		after, err := multiHubDockerBusinessRows(root, e.Name)
		if err != nil || after != before {
			return errors.New("Control503 mutated peer business rows")
		}
		result = append(result, map[string]any{"hub": e.Name, "case": "Control-absent-key-manifest-denied", "status": 503, "business_rows_unchanged": true})
	}
	return json.NewEncoder(os.Stdout).Encode(map[string]any{"cases": result, "result": "PASS"})
}

func multiHubDockerEnroll(root string) error {
	if err := multiHubDockerPrivateRoot(root); err != nil {
		return err
	}
	sender, err := multiHubDockerLoad(filepath.Join(root, "node"))
	if err != nil {
		return err
	}
	receiver, err := multiHubDockerLoad(filepath.Join(root, "node-r"))
	if err != nil {
		return err
	}
	result := []map[string]any{}
	for i, e := range sender {
		client := &http.Client{Timeout: time.Second, Transport: &http.Transport{Proxy: nil}}
		ready := false
		deadline := time.Now().Add(20 * time.Second)
		for time.Now().Before(deadline) {
			resp, healthErr := client.Get(e.Target + "/healthz")
			if healthErr == nil {
				resp.Body.Close()
				if resp.StatusCode == 200 {
					ready = true
					break
				}
			}
			time.Sleep(200 * time.Millisecond)
		}
		if !ready {
			return errors.New("bounded production Hub health readiness failed")
		}
		var meta multiHubDockerOperator
		dir := filepath.Join(root, "operator", e.Name)
		if err = multiHubDockerReadPrivate(filepath.Join(dir, "metadata.json"), &meta); err != nil {
			return err
		}
		if len(meta.Joins) != 2 || len(meta.Registered) != 0 {
			return errors.New("fresh two-session Join metadata required")
		}
		owner, err := multiHubDockerSigner(filepath.Join(dir, "owner.key"))
		if err != nil {
			return err
		}
		for n, entry := range []multiHubDockerEntry{e, receiver[i]} {
			var joined fabric.NetworkJoinResult
			if err = multiHubDockerHTTP(e.Target, "/v2/fabric/node/networks/join", "CicadaNode "+entry.Token, meta.Joins[n], &joined, 201); err != nil {
				return err
			}
			if joined.NetworkID != e.NetworkID || joined.Endpoint.MachineID != entry.NodeID || joined.Endpoint.NativeSessionID != meta.Joins[n].NativeSessionID || joined.BindingEpoch == 0 || joined.SessionToken == "" {
				return errors.New("production Join response has wrong scoped binding")
			}
			nodeName := []string{"node", "node-r"}[n]
			nodeDir := machineNodeStateDir(filepath.Join(root, nodeName, entry.StateRelative), entry.NodeID)
			identity, err := nodekeys.LoadOrCreate(nodeDir, joined.Endpoint.ID)
			if err != nil {
				return err
			}
			path := "/v2/fabric/networks/" + e.NetworkID + "/direct/"
			var binding store.NetworkDirectNativeBinding
			if err = multiHubDockerHTTP(e.Target, path+"native-binding", "Cicada-Network-Session "+joined.SessionToken, map[string]any{}, &binding, 200); err != nil {
				return err
			}
			if binding.NodeID != entry.NodeID || binding.EndpointID != joined.Endpoint.ID || binding.NativeSessionID != meta.Joins[n].NativeSessionID || binding.Epoch == 0 {
				return errors.New("exact current synthetic native binding required")
			}
			attestation, err := identity.SignNetworkDirectKeyAttestation(e.HubID, e.NetworkID, joined.Endpoint.ID, joined.Endpoint.PrincipalID, entry.NodeID, binding.ID, binding.Epoch)
			if err != nil {
				return err
			}
			var candidate store.NetworkDirectKeyCandidate
			if err = multiHubDockerHTTP(e.Target, path+"key-candidate", "Cicada-Network-Session "+joined.SessionToken, map[string][]byte{"attestation": attestation}, &candidate, 201); err != nil {
				return err
			}
			var manifest store.NetworkDirectKeyManifest
			if err = multiHubDockerControlRPC(root, e, &meta, "network.key_manifest", map[string]string{"network_id": e.NetworkID, "endpoint_id": joined.Endpoint.ID, "owner_key_id": owner.Public().ID}, &manifest); err != nil {
				return err
			}
			digest, err := manifest.CanonicalDigest()
			if err != nil || digest != manifest.Digest || manifest.Candidate.Public.ID != identity.Public().ID || manifest.NodeID != entry.NodeID {
				return errors.New("current Control manifest differs from exact Endpoint candidate")
			}
			proof, err := owner.SignOwnerNetworkDirectKeyGrant(e.HubID, e.NetworkID, joined.Endpoint.ID, e.OwnerID, digest, time.Now().Add(-time.Minute), time.Now().Add(time.Hour))
			if err != nil {
				return err
			}
			var grant store.OwnerNetworkDirectKeyGrant
			if err = multiHubDockerControlRPC(root, e, &meta, "network.key_grant", map[string]any{"network_id": e.NetworkID, "endpoint_id": joined.Endpoint.ID, "signed_proof": proof}, &grant); err != nil {
				return err
			}
			if grant.State != "active" || grant.ManifestDigest != digest {
				return errors.New("Control did not accept exact Network key consent")
			}
			meta.Registered = append(meta.Registered, joined)
			meta.NativeBindings = append(meta.NativeBindings, binding)
			result = append(result, map[string]any{"hub": e.Name, "hub_id": e.HubID, "network_id": e.NetworkID, "node_id": entry.NodeID, "endpoint_id": joined.Endpoint.ID, "join_http": 201, "key_consent": "ACTIVE", "native_runtime": "NOT_RUN", "scope": "production Hub enrollment of visibly synthetic session"})
		}
		if err = multiHubDockerWrite(filepath.Join(dir, "metadata.json"), meta); err != nil {
			return err
		}
	}
	for i, e := range sender {
		var current, other multiHubDockerOperator
		if err = multiHubDockerReadPrivate(filepath.Join(root, "operator", e.Name, "metadata.json"), &current); err != nil {
			return err
		}
		if err = multiHubDockerReadPrivate(filepath.Join(root, "operator", sender[1-i].Name, "metadata.json"), &other); err != nil {
			return err
		}
		for _, test := range []struct {
			name, path, token string
			body              any
			want              int
		}{
			{"foreign_Hub_Network_session", "/v2/fabric/networks/" + e.NetworkID + "/direct/native-binding", other.Registered[0].SessionToken, map[string]any{}, 401},
			{"wrong_Network_selector", "/v2/fabric/networks/net_wrong_synthetic/direct/native-binding", current.Registered[0].SessionToken, map[string]any{}, 401},
			{"foreign_Hub_Endpoint_recipient", "/v2/fabric/networks/" + e.NetworkID + "/direct/peer-key", current.Registered[0].SessionToken, map[string]string{"target_endpoint_id": other.Registered[1].Endpoint.ID}, 404},
		} {
			before, err := multiHubDockerBusinessRows(root, e.Name)
			if err != nil {
				return err
			}
			if err = multiHubDockerHTTP(e.Target, test.path, "Cicada-Network-Session "+test.token, test.body, nil, test.want); err != nil {
				return err
			}
			after, err := multiHubDockerBusinessRows(root, e.Name)
			if err != nil || after != before {
				return errors.New("denied Network request mutated business rows")
			}
			result = append(result, map[string]any{"hub": e.Name, "case": test.name, "status": test.want, "business_rows_unchanged": true})
		}
	}

	return json.NewEncoder(os.Stdout).Encode(map[string]any{"cases": result, "result": "PASS"})
}

type multiHubDockerOpaqueMessage struct {
	Path         string                    `json:"path"`
	Input        json.RawMessage           `json:"input"`
	Context      e2ee.NetworkDirectContext `json:"context"`
	Ciphertext   []byte                    `json:"ciphertext"`
	Payload      []byte                    `json:"payload"`
	ReceiverNode string                    `json:"receiver_node"`
}

func multiHubDockerSeal(root string, e, receiver multiHubDockerEntry, m multiHubDockerOperator, kind string) (multiHubDockerOpaqueMessage, error) {
	n := 0
	entry := e
	if kind == "REPLY" {
		n = 1
		entry = receiver
	}
	source, target := m.Registered[n], m.Registered[1-n]
	path := "/v2/fabric/networks/" + e.NetworkID + "/direct/"
	var bundle store.NetworkDirectPeerBundle
	msg, request, replyTo := "multihub_send", "", ""
	if kind == "REQUEST" {
		msg, request = "multihub_ask", "multihub_request"
	}
	if kind == "REPLY" {
		msg, request, replyTo = "multihub_reply", "multihub_request", "multihub_ask"
		var route store.NetworkDirectReplyRoute
		if err := multiHubDockerHTTP(e.Target, "/v2/fabric/node/networks/direct/reply-route", "CicadaNode "+entry.Token, map[string]string{"network_id": e.NetworkID, "network_session_token": source.SessionToken, "request_id": request}, &route, 200); err != nil {
			return multiHubDockerOpaqueMessage{}, err
		}
		if route.RequestID != request || route.RequestMessageID != replyTo || route.Bundle == nil {
			return multiHubDockerOpaqueMessage{}, errors.New("current exact correlated reply route required")
		}
		bundle = *route.Bundle
	} else {
		if err := multiHubDockerHTTP(e.Target, path+"peer-key", "Cicada-Network-Session "+source.SessionToken, map[string]string{"target_endpoint_id": target.Endpoint.ID}, &bundle, 200); err != nil {
			return multiHubDockerOpaqueMessage{}, err
		}
	}
	if bundle.HubID != e.HubID || bundle.NetworkID != e.NetworkID || bundle.Sender.Manifest.EndpointID != source.Endpoint.ID || bundle.Receiver.Manifest.EndpointID != target.Endpoint.ID {
		return multiHubDockerOpaqueMessage{}, errors.New("peer-key bundle scope mismatch")
	}
	routeContext := store.NetworkDirectContext(&bundle, msg, kind, request, replyTo)
	nodeName := []string{"node", "node-r"}[n]
	dir := machineNodeStateDir(filepath.Join(root, nodeName, entry.StateRelative), entry.NodeID)
	identity, err := nodekeys.LoadExisting(dir, source.Endpoint.ID)
	if err != nil {
		return multiHubDockerOpaqueMessage{}, err
	}
	state, err := nodekeys.OpenCryptoState(dir)
	if err != nil {
		return multiHubDockerOpaqueMessage{}, err
	}
	defer state.Close()
	senderEvidence, err := networkDirectEvidence(bundle.Sender)
	if err != nil {
		return multiHubDockerOpaqueMessage{}, err
	}
	receiverEvidence, err := networkDirectEvidence(bundle.Receiver)
	if err != nil {
		return multiHubDockerOpaqueMessage{}, err
	}
	payload := []byte("CICADA-MULTIHUB-SYNTHETIC-OPAQUE-" + e.Name + "-" + kind)
	operation, err := nodekeys.NetworkDirectOperationID(routeContext, payload)
	if err != nil {
		return multiHubDockerOpaqueMessage{}, err
	}
	sealed, err := state.SealOutboundNetworkDirectMessage(context.Background(), identity, routeContext, senderEvidence, receiverEvidence, operation, payload)
	if err != nil {
		return multiHubDockerOpaqueMessage{}, err
	}
	var input any
	verb := "send"
	switch kind {
	case "SEND":
		input = fabric.NetworkDirectSendInput{NetworkID: e.NetworkID, NetworkSessionToken: source.SessionToken, TargetEndpointID: target.Endpoint.ID, MessageID: msg, IdempotencyKey: msg, Ciphertext: sealed.Envelope}
	case "REQUEST":
		verb = "ask"
		input = fabric.NetworkDirectAskInput{NetworkID: e.NetworkID, NetworkSessionToken: source.SessionToken, TargetEndpointID: target.Endpoint.ID, MessageID: msg, RequestID: request, IdempotencyKey: msg, ExpiresAt: time.Now().UTC().Add(30 * time.Minute).Format(time.RFC3339Nano), Ciphertext: sealed.Envelope}
	case "REPLY":
		verb = "reply"
		input = fabric.NetworkDirectReplyInput{NetworkID: e.NetworkID, NetworkSessionToken: source.SessionToken, MessageID: msg, RequestID: request, IdempotencyKey: msg, Ciphertext: sealed.Envelope}
	}
	encoded, err := json.Marshal(input)
	if err != nil {
		return multiHubDockerOpaqueMessage{}, err
	}
	return multiHubDockerOpaqueMessage{Path: "/v2/fabric/node/networks/direct/" + verb, Input: encoded, Context: routeContext, Ciphertext: sealed.Envelope, Payload: payload, ReceiverNode: []string{"node-r", "node"}[n]}, nil
}

// Separate name avoids shadowing context package with the production tuple.
func multiHubDockerBusinessRows(root, name string) (string, error) {
	db, err := sql.Open("sqlite", "file:"+filepath.Join(root, "hubs", name, "state/cicada.sqlite3")+"?mode=ro")
	if err != nil {
		return "", err
	}
	defer db.Close()
	var joined string
	for _, table := range []string{"fabric_messages", "relay_v2_requests", "relay_v2_message_payloads", "network_direct_message_routes_v2", "relay_v2_request_events"} {
		rows, err := db.Query("SELECT * FROM " + table + " ORDER BY 1")
		if err != nil {
			return "", err
		}
		cols, err := rows.Columns()
		if err != nil {
			rows.Close()
			return "", err
		}
		data := [][]any{}
		for rows.Next() {
			values := make([]any, len(cols))
			ptrs := make([]any, len(cols))
			for i := range values {
				ptrs[i] = &values[i]
			}
			if err = rows.Scan(ptrs...); err != nil {
				rows.Close()
				return "", err
			}
			data = append(data, values)
		}
		err = rows.Err()
		rows.Close()
		if err != nil {
			return "", err
		}
		wire, err := json.Marshal(data)
		if err != nil {
			return "", err
		}
		joined += table + string(wire)
	}
	digest := sha256.Sum256([]byte(joined))
	return hex.EncodeToString(digest[:]), nil
}
func multiHubDockerMessages(root, phase string) error {
	if err := multiHubDockerPrivateRoot(root); err != nil {
		return err
	}
	sender, err := multiHubDockerLoad(filepath.Join(root, "node"))
	if err != nil {
		return err
	}
	receiver, err := multiHubDockerLoad(filepath.Join(root, "node-r"))
	if err != nil {
		return err
	}
	results := []map[string]any{}
	for i, e := range sender {
		var meta multiHubDockerOperator
		dir := filepath.Join(root, "operator", e.Name)
		if err = multiHubDockerReadPrivate(filepath.Join(dir, "metadata.json"), &meta); err != nil {
			return err
		}
		if len(meta.Registered) != 2 {
			return errors.New("actual two-endpoint enrollment required")
		}
		kinds := []string{"SEND", "REQUEST"}
		if phase == "reply" {
			kinds = []string{"REPLY"}
		}
		if phase == "replay" {
			kinds = []string{"SEND", "REQUEST", "REPLY"}
		}
		for _, kind := range kinds {
			path := filepath.Join(dir, kind+".json")
			var message multiHubDockerOpaqueMessage
			if phase == "replay" {
				if err = multiHubDockerReadPrivate(path, &message); err != nil {
					return err
				}
			} else {
				message, err = multiHubDockerSeal(root, e, receiver[i], meta, kind)
				if err != nil {
					return err
				}
				if err = multiHubDockerWrite(path, message); err != nil {
					return err
				}
			}
			entry := e
			if kind == "REPLY" {
				entry = receiver[i]
			}
			// Hub B has the same Network/message/request IDs, but independent authority.
			// Transplant the real envelope with B's otherwise valid credentials.
			if phase != "replay" && i == 1 {
				var wrong multiHubDockerOpaqueMessage
				if err = multiHubDockerReadPrivate(filepath.Join(root, "operator/a", kind+".json"), &wrong); err != nil {
					return err
				}
				var body map[string]any
				if err = json.Unmarshal(message.Input, &body); err != nil {
					return err
				}
				body["ciphertext"] = wrong.Ciphertext
				before, err := multiHubDockerBusinessRows(root, e.Name)
				if err != nil {
					return err
				}
				if err = multiHubDockerHTTP(e.Target, message.Path, "CicadaNode "+entry.Token, body, nil, 403); err != nil {
					return err
				}
				after, err := multiHubDockerBusinessRows(root, e.Name)
				if err != nil || after != before {
					return errors.New("wrong-Hub envelope mutated business rows")
				}
				results = append(results, map[string]any{"hub": e.Name, "case": "wrong_Hub_" + kind + "_ciphertext", "status": 403, "business_rows_unchanged": true})
			}
			if phase == "messages" && i == 0 && kind == "SEND" {
				req, err := http.NewRequest(http.MethodPost, "http://node-sender:18871"+message.Path, bytes.NewReader(message.Input))
				if err != nil {
					return err
				}
				req.Header.Set("Authorization", "CicadaNode "+entry.Token)
				req.Header.Set("Content-Type", "application/json")
				req.Header.Set("X-Cicada-Fixture-Probe", "1")
				req.Header.Set("X-Cicada-Fixture-Lose-Reply", "1")
				client := &http.Client{Timeout: 10 * time.Second, Transport: &http.Transport{Proxy: nil}}
				response, err := client.Do(req)
				if err != nil {
					return errors.New("bounded synthetic lost-response request unavailable")
				}
				_, _ = io.Copy(io.Discard, io.LimitReader(response.Body, 4096))
				response.Body.Close()
				if response.StatusCode != 502 {
					return errors.New("observer did not lose actual Hub acceptance response")
				}
				db, err := sql.Open("sqlite", "file:"+filepath.Join(root, "hubs", e.Name, "state/cicada.sqlite3")+"?mode=ro")
				if err != nil {
					return err
				}
				var saved []byte
				err = db.QueryRow(`SELECT ciphertext FROM relay_v2_message_payloads WHERE message_id=?`, message.Context.MessageID).Scan(&saved)
				db.Close()
				if err != nil || !bytes.Equal(saved, message.Ciphertext) {
					return errors.New("lost response lacked actual committed Hub ciphertext")
				}
				results = append(results, map[string]any{"hub": e.Name, "case": "lost_response_after_real_Hub_acceptance", "front_status": 502, "actual_Hub_ciphertext_committed": true, "retry": "same saved message ID and exact ciphertext", "runtime": "NOT_RUN"})
			}

			var input any
			if err = json.Unmarshal(message.Input, &input); err != nil {
				return err
			}
			var accepted map[string]any
			if err = multiHubDockerHTTP(e.Target, message.Path, "CicadaNode "+entry.Token, input, &accepted, 202); err != nil {
				return err
			}
			if kind == "SEND" {
				var record store.RelaySealedV1Record
				wire, _ := json.Marshal(accepted)
				if json.Unmarshal(wire, &record) != nil || record.Route.MessageID != message.Context.MessageID || !bytes.Equal(record.Ciphertext, message.Ciphertext) {
					return errors.New("Hub SEND acceptance differs from exact opaque envelope")
				}
			} else {
				wire, _ := json.Marshal(accepted)
				var req store.FabricRequest
				if json.Unmarshal(wire, &req) != nil || req.RequestID != message.Context.RequestID || req.MessageID != "multihub_ask" || kind == "REPLY" && req.ReplyMessageID != "multihub_reply" {
					return errors.New("Hub ASK/REPLY acceptance miscorrelated")
				}
			}
			digest := sha256.Sum256(message.Ciphertext)
			results = append(results, map[string]any{"hub": e.Name, "hub_id": e.HubID, "network_id": e.NetworkID, "kind": kind, "message_id": message.Context.MessageID, "request_id": message.Context.RequestID, "reply_to": message.Context.ReplyTo, "ciphertext_sha256": hex.EncodeToString(digest[:]), "http": 202, "layer": "RELAY_ACCEPTED", "retry": phase == "replay", "native_runtime": "NOT_RUN"})
		}
	}
	return json.NewEncoder(os.Stdout).Encode(map[string]any{"cases": results, "result": "PASS"})
}

func multiHubDockerInspectOnce(root string, includeReply bool) ([]map[string]any, error) {
	sender, err := multiHubDockerLoad(filepath.Join(root, "node"))
	if err != nil {
		return nil, err
	}
	receiver, err := multiHubDockerLoad(filepath.Join(root, "node-r"))
	if err != nil {
		return nil, err
	}
	results := []map[string]any{}
	for i, e := range sender {
		var actualJoin multiHubDockerOperator
		if err = multiHubDockerReadPrivate(filepath.Join(root, "operator", e.Name, "metadata.json"), &actualJoin); err != nil {
			return nil, err
		}
		if len(actualJoin.Registered) != 2 || len(actualJoin.NativeBindings) != 2 {
			return nil, errors.New("actual two-endpoint Join tuple required")
		}
		kinds := []string{"SEND", "REQUEST"}
		if includeReply {
			kinds = append(kinds, "REPLY")
		}
		for _, kind := range kinds {
			var message multiHubDockerOpaqueMessage
			if err = multiHubDockerReadPrivate(filepath.Join(root, "operator", e.Name, kind+".json"), &message); err != nil {
				return nil, err
			}
			entry := receiver[i]
			receiverJoin := actualJoin.Registered[1]
			receiverBinding := actualJoin.NativeBindings[1]
			if kind == "REPLY" {
				entry = e
				receiverJoin = actualJoin.Registered[0]
				receiverBinding = actualJoin.NativeBindings[0]
			}
			if receiverJoin.Endpoint.ID != message.Context.ReceiverEndpointID || receiverJoin.Endpoint.MachineID != entry.NodeID || receiverBinding.ID == "" || receiverBinding.EndpointID != receiverJoin.Endpoint.ID || receiverBinding.NodeID != entry.NodeID || receiverBinding.NativeSessionID != receiverJoin.Endpoint.NativeSessionID || receiverBinding.Epoch != message.Context.ReceiverBindingEpoch || receiverJoin.NetworkID != e.NetworkID {
				return nil, errors.New("ciphertext recipient differs from actual registered Join tuple")
			}
			dir := machineNodeStateDir(filepath.Join(root, message.ReceiverNode, entry.StateRelative), entry.NodeID)
			identity, err := nodekeys.LoadExisting(dir, message.Context.ReceiverEndpointID)
			if err != nil {
				return nil, err
			}
			sourceEntry, sourceNode := e, "node"
			if kind == "REPLY" {
				sourceEntry, sourceNode = receiver[i], "node-r"
			}
			author, err := nodekeys.LoadExisting(machineNodeStateDir(filepath.Join(root, sourceNode, sourceEntry.StateRelative), sourceEntry.NodeID), message.Context.SenderEndpointID)
			if err != nil {
				return nil, err
			}
			db, err := sql.Open("sqlite", "file:"+filepath.Join(dir, "node-crypto-state.sqlite")+"?mode=ro")
			if err != nil {
				return nil, err
			}
			var envelope, digest, replayDigest []byte
			var sequence, replaySequence, count int64
			err = func() error {
				defer db.Close()
				tx, err := db.BeginTx(context.Background(), &sql.TxOptions{ReadOnly: true})
				if err != nil {
					return err
				}
				defer tx.Rollback()
				if err = tx.QueryRow(`SELECT envelope,digest,sequence FROM node_crypto_inbox WHERE receiver_endpoint_id=? AND sender_key_id=? AND message_id=?`, message.Context.ReceiverEndpointID, message.Context.SenderKeyID, message.Context.MessageID).Scan(&envelope, &digest, &sequence); err != nil {
					return err
				}
				if err = tx.QueryRow(`SELECT digest,sequence FROM node_crypto_replay WHERE receiver_endpoint_id=? AND sender_key_id=? AND message_id=?`, message.Context.ReceiverEndpointID, message.Context.SenderKeyID, message.Context.MessageID).Scan(&replayDigest, &replaySequence); err != nil {
					return err
				}
				return tx.QueryRow(`SELECT count(*) FROM node_crypto_replay WHERE message_id=?`, message.Context.MessageID).Scan(&count)
			}()
			if err != nil {
				return nil, err
			}
			actual := sha256.Sum256(envelope)
			if count != 1 || sequence <= 0 || sequence != replaySequence || !bytes.Equal(digest, actual[:]) || !bytes.Equal(digest, replayDigest) || !bytes.Equal(envelope, message.Ciphertext) {
				return nil, errors.New("production Node stored ciphertext/replay mismatch")
			}
			plain, verifiedSequence, err := e2ee.OpenNetworkDirectMessage(identity, author.Public(), message.Context, envelope)
			if err != nil || verifiedSequence != uint64(sequence) || !bytes.Equal(plain, message.Payload) {
				return nil, errors.New("production Node ciphertext cannot open to exact synthetic payload")
			}
			inbox, err := sql.Open("sqlite", "file:"+filepath.Join(dir, "inbox.sqlite")+"?mode=ro")
			if err != nil {
				return nil, err
			}
			var payload []byte
			var state, endpoint, session, storedDigest string
			var epoch uint64
			err = inbox.QueryRow(`SELECT payload,state,endpoint_id,session_id,binding_epoch,digest FROM node_inbox_deliveries WHERE message_id=?`, message.Context.MessageID).Scan(&payload, &state, &endpoint, &session, &epoch, &storedDigest)
			inbox.Close()
			if err != nil || !bytes.Equal(payload, plain) || endpoint != message.Context.ReceiverEndpointID || epoch != message.Context.ReceiverBindingEpoch || storedDigest != hex.EncodeToString(actual[:]) || session != receiverJoin.Endpoint.NativeSessionID {
				return nil, errors.New("production Node inbox does not bind exact decrypted payload")
			}
			if state != "NODE_RECEIVED" && state != "FAILED" {
				return nil, errors.New("unexpected Runtime/queue transition in zero-runtime gate")
			}
			hub, err := sql.Open("sqlite", "file:"+filepath.Join(root, "hubs", e.Name, "state/cicada.sqlite3")+"?mode=ro")
			if err != nil {
				return nil, err
			}
			var received, unsafe int
			err = hub.QueryRow(`SELECT count(*) FROM relay_v2_receipts WHERE message_id=? AND layer=? AND target_endpoint_id=? AND digest=? AND binding_id=? AND binding_epoch=?`, message.Context.MessageID, store.RelayReceiptNodeReceived, endpoint, storedDigest, receiverBinding.ID, receiverBinding.Epoch).Scan(&received)
			if err == nil {
				err = hub.QueryRow(`SELECT count(*) FROM relay_v2_receipts WHERE message_id=? AND layer NOT IN (?,?,?)`, message.Context.MessageID, store.RelayReceiptAccepted, store.RelayReceiptNodeReceived, store.RelayReceiptFailed).Scan(&unsafe)
			}
			layers := map[string]int{}
			if err == nil {
				var rows *sql.Rows
				rows, err = hub.Query(`SELECT layer,count(*) FROM relay_v2_receipts WHERE message_id=? GROUP BY layer`, message.Context.MessageID)
				if err == nil {
					for rows.Next() {
						var layer string
						var count int
						if err = rows.Scan(&layer, &count); err != nil {
							break
						}
						layers[layer] = count
					}
					if err == nil {
						err = rows.Err()
					}
					rows.Close()
				}
			}
			hub.Close()
			if err != nil || received < 1 || unsafe != 0 {
				return nil, errors.New("missing real Node receipt or unexpected synthetic execution receipt")
			}
			results = append(results, map[string]any{"hub": e.Name, "hub_id": e.HubID, "network_id": e.NetworkID, "node_id": entry.NodeID, "message_id": message.Context.MessageID, "kind": kind, "ciphertext_sha256": hex.EncodeToString(actual[:]), "crypto_sequence": sequence, "replay_rows": count, "exact_ciphertext_open_payload_match": true, "node_inbox_state": state, "layer": "NODE_RECEIVED", "higher_receipt_count": unsafe, "actual_receipt_layers": layers, "consumption": "CONSUMPTION_UNCONFIRMED"})
		}
		if includeReply {
			var meta multiHubDockerOperator
			if err = multiHubDockerReadPrivate(filepath.Join(root, "operator", e.Name, "metadata.json"), &meta); err != nil {
				return nil, err
			}
			// Request status uses the sender's authenticated Network session, not DB fabrication.
			req, _ := http.NewRequest(http.MethodGet, e.Target+"/v2/fabric/networks/"+e.NetworkID+"/direct/request-status?request_id=multihub_request", nil)
			req.Header.Set("Authorization", "Cicada-Network-Session "+meta.Registered[0].SessionToken)
			client := &http.Client{Timeout: 5 * time.Second, Transport: &http.Transport{Proxy: nil}}
			resp, err := client.Do(req)
			if err != nil {
				return nil, err
			}
			var status store.FabricRequest
			decodeErr := json.NewDecoder(io.LimitReader(resp.Body, 16384)).Decode(&status)
			resp.Body.Close()
			if decodeErr != nil || resp.StatusCode != 200 || status.RequestID != "multihub_request" || status.MessageID != "multihub_ask" || status.ReplyMessageID != "multihub_reply" || status.SenderEndpointID != meta.Registered[0].Endpoint.ID || status.ReceiverEndpointID != meta.Registered[1].Endpoint.ID || status.State != "REPLIED" {
				return nil, errors.New("actual per-Hub request status/correlation mismatch")
			}
		}
	}
	return results, nil
}
func multiHubDockerInspect(root string, includeReply bool) error {
	if err := multiHubDockerPrivateRoot(root); err != nil {
		return err
	}
	deadline := time.Now().Add(40 * time.Second)
	var last error
	for time.Now().Before(deadline) {
		cases, err := multiHubDockerInspectOnce(root, includeReply)
		if err == nil {
			return json.NewEncoder(os.Stdout).Encode(map[string]any{"cases": cases, "result": "PASS"})
		}
		last = err
		time.Sleep(200 * time.Millisecond)
	}
	return fmt.Errorf("bounded production Node persistence check: %w", last)
}

func TestMachineMultiHubDockerFixture(t *testing.T) {
	action := os.Getenv("CICADA_MULTI_HUB_FIXTURE_ACTION")
	if action == "" {
		t.Skip("explicit disposable Docker fixture action required")
	}
	root := os.Getenv("CICADA_MULTI_HUB_FIXTURE_ROOT")
	var err error
	switch action {
	case "seed":
		err = multiHubDockerSeed(root)
	case "runtime":
		err = multiHubDockerRuntime(root)
	case "probe":
		err = multiHubDockerProbe(root)
	case "control-absent":
		err = multiHubDockerControlAbsent(root)
	case "enroll":
		err = multiHubDockerEnroll(root)
	case "messages", "reply", "replay":
		err = multiHubDockerMessages(root, action)
	case "received":
		err = multiHubDockerInspect(root, false)
	case "inspect":
		err = multiHubDockerInspect(root, true)
	default:
		err = errors.New("unknown disposable fixture action")
	}
	if err != nil {
		t.Fatal(err)
	}
}

func TestMachineMultiHubDockerFixtureRejectsUnownedAndSharedCoordinates(t *testing.T) {
	root := t.TempDir()
	_ = os.Chmod(root, 0700)
	if multiHubDockerPrivateRoot(root) == nil {
		t.Fatal("unowned root accepted")
	}
	if err := os.WriteFile(filepath.Join(root, ".multi-hub-owned"), []byte("cicada.multihub.disposable.v1\nsynthetic-test\n"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := multiHubDockerPrivateRoot(root); err != nil {
		t.Fatal(err)
	}
	if err := multiHubDockerWrite(filepath.Join(root, "proxy.json"), []multiHubDockerEntry{{HubID: "same", Token: "a"}, {HubID: "same", Token: "b"}}); err != nil {
		t.Fatal(err)
	}
	if _, err := multiHubDockerLoad(root); err == nil {
		t.Fatal("colliding Hub coordinate accepted")
	}
	if err := os.Chmod(filepath.Join(root, "proxy.json"), 0644); err != nil {
		t.Fatal(err)
	}
	if _, err := multiHubDockerLoad(root); err == nil {
		t.Fatal("nonprivate credentials accepted")
	}
}

func TestMachineMultiHubDockerHTTPRequiresExactStatusAndTypedDenial(t *testing.T) {
	const sentinel = "SYNTHETIC-PRIVATE-HTTP-RESPONSE"
	for _, test := range []struct {
		name    string
		status  int
		body    string
		wantErr bool
	}{
		{"typed", 403, `{"error":"Network operation denied"}`, false},
		{"untyped", 403, `{"error":123}`, true},
		{"empty", 403, `{}`, true},
		{"wrong-status", 500, `{"error":"` + sentinel + `"}`, true},
	} {
		t.Run(test.name, func(t *testing.T) {
			hub := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.Header.Get("Authorization") != "CicadaNode synthetic-token" {
					t.Error("wrong trusted authorization")
				}
				w.WriteHeader(test.status)
				_, _ = io.WriteString(w, test.body)
			}))
			defer hub.Close()
			err := multiHubDockerHTTP(hub.URL, "/v2/fabric/node/networks/direct/send", "CicadaNode synthetic-token", map[string]string{}, nil, 403)
			if (err != nil) != test.wantErr {
				t.Fatalf("typed exact status check: %v", err)
			}
			if err != nil && strings.Contains(err.Error(), sentinel) {
				t.Fatal("private HTTP body leaked in error")
			}
		})
	}
}
func TestMachineMultiHubDockerObserverPreservesStreamAndRejectsFalseReady(t *testing.T) {
	for _, test := range []struct {
		name, wire string
		want       int
	}{
		{"ready", "event: ready\ndata: claim\n\n", 1},
		{"different-event", "event: other\ndata: claim\n\n", 0},
		{"different-data", "event: ready\ndata: wrong\n\n", 0},
	} {
		t.Run(test.name, func(t *testing.T) {
			count := 0
			reader := &multiHubDockerObservedBody{ReadCloser: io.NopCloser(strings.NewReader(test.wire)), mark: func() { count++ }}
			output := []byte{}
			for {
				b := make([]byte, 3)
				n, err := reader.Read(b)
				output = append(output, b[:n]...)
				if err == io.EOF {
					break
				}
				if err != nil {
					t.Fatal(err)
				}
			}
			if string(output) != test.wire || count != test.want || reader.prefix != nil {
				t.Fatalf("stream/ready evidence changed: count=%d", count)
			}
		})
	}
}
