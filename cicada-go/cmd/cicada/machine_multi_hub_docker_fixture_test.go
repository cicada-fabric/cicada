package main

// This helper seeds and observes disposable fixtures only. Hub and Agent run
// the exact production binary extracted from the reviewed clean Hub image.
import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
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

	"github.com/cicada-ai/cicada/internal/e2ee"
	"github.com/cicada-ai/cicada/internal/fabric"
	"github.com/cicada-ai/cicada/internal/nodeinbox"
	"github.com/cicada-ai/cicada/internal/nodekeys"
	"github.com/cicada-ai/cicada/internal/store"
)

type multiHubDockerEntry struct {
	Name              string `json:"name"`
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
	Heartbeats       int `json:"heartbeats_ok"`
	Claims           int `json:"sealed_claims_ok"`
	GroupClaims      int `json:"group_claims_ok"`
	SSEHeaders       int `json:"sse_headers_ok"`
	SSEReady         int `json:"sse_ready_frames"`
	WrongAgentBearer int `json:"wrong_agent_bearer"`
	ControlRequests  int `json:"control_requests"`
	UpstreamFailures int `json:"upstream_failures"`
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

func multiHubDockerSeed(root string) error {
	if err := multiHubDockerPrivateRoot(root); err != nil {
		return err
	}
	if _, err := os.Lstat(filepath.Join(root, "node")); !errors.Is(err, os.ErrNotExist) {
		return errors.New("refuse existing fixture state")
	}
	nodeRoot := filepath.Join(root, "node")
	writerRoot := filepath.Join(nodeRoot, "state")
	if err := os.MkdirAll(writerRoot, 0700); err != nil {
		return err
	}
	marker, err := os.ReadFile(filepath.Join(root, ".multi-hub-owned"))
	if err != nil {
		return err
	}
	if err = os.WriteFile(filepath.Join(nodeRoot, ".multi-hub-owned"), marker, 0600); err != nil {
		return err
	}
	entries := []multiHubDockerEntry{}
	configs := []machineHubConfig{}
	for index, name := range []string{"a", "b"} {
		state := filepath.Join(root, "hubs", name, "state")
		if err = os.MkdirAll(filepath.Join(state, "e2ee"), 0700); err != nil {
			return err
		}
		if err = os.MkdirAll(filepath.Join(root, "hubs", name, "workspace"), 0700); err != nil {
			return err
		}
		hub, makeErr := e2ee.NewIdentity()
		if makeErr != nil {
			return makeErr
		}
		wire, makeErr := hub.MarshalBinary()
		if makeErr != nil {
			return makeErr
		}
		if err = os.WriteFile(filepath.Join(state, "e2ee", "identity.json"), wire, 0600); err != nil {
			return err
		}
		controlKey, makeErr := e2ee.NewIdentity()
		if makeErr != nil {
			return makeErr
		}
		wire, makeErr = controlKey.MarshalBinary()
		if makeErr != nil {
			return makeErr
		}
		if err = os.WriteFile(filepath.Join(state, "e2ee", "client-control-identity.json"), wire, 0600); err != nil {
			return err
		}
		db, makeErr := store.New(filepath.Join(state, "cicada.sqlite3"))
		if makeErr != nil {
			return makeErr
		}
		entry := multiHubDockerEntry{Name: name, OwnerID: hub.Public().ID, NodeID: "node_multihub_synthetic", Target: "http://hub-" + name + ":8787", Origin: fmt.Sprintf("http://127.0.0.1:%d", 18871+index)}
		entry.HubID, err = db.GetClientHubID()
		if err != nil {
			db.Close()
			return err
		}
		config := machineHubConfig{HubID: entry.HubID, ControlURL: entry.Origin, NodeID: entry.NodeID, Name: "synthetic multi-Hub " + name}
		entry.StateRelative = strings.TrimPrefix(machineHubStateDir(writerRoot, config), nodeRoot+string(filepath.Separator))
		for foreign := 0; foreign < 2; foreign++ {
			owner, makeErr := e2ee.NewIdentity()
			if makeErr != nil {
				db.Close()
				return makeErr
			}
			ownerID, nodeID := entry.OwnerID, entry.NodeID
			if foreign == 1 {
				ownerID = owner.Public().ID
				nodeID = "node_foreign_owner_" + name
			}
			if _, err = db.CreatePrincipal(store.Principal{ID: ownerID, Kind: store.PrincipalKindHuman, OwnerID: ownerID, TrustDomainID: ownerID, Name: "Synthetic fixture Owner", Status: store.PrincipalStatusActive}); err != nil {
				db.Close()
				return err
			}
			key, makeErr := db.RegisterOwnerApprovalKeyLocal(ownerID, owner.Public())
			if makeErr != nil {
				db.Close()
				return makeErr
			}
			device, makeErr := e2ee.NewIdentity()
			if makeErr != nil {
				db.Close()
				return makeErr
			}
			deviceID := fmt.Sprintf("device_multi_%s_%d", name, foreign)
			grant, makeErr := owner.SignOwnerDeviceGrant(ownerID, deviceID, device.Public(), entry.HubID, e2ee.OwnerDevicePurposeControl, time.Now().Add(-time.Minute), time.Now().Add(time.Hour))
			if makeErr != nil {
				db.Close()
				return makeErr
			}
			if _, err = db.RegisterClientDeviceFromOwnerGrant(store.RegisterClientDeviceInput{OwnerID: ownerID, OwnerKeyID: key.KeyID, DeviceID: deviceID, DevicePublic: device.Public(), OwnerDeviceGrant: grant}); err != nil {
				db.Close()
				return err
			}
			token, digest, makeErr := fabric.NewNodeCredential()
			if makeErr != nil {
				db.Close()
				return makeErr
			}
			code := sha256.Sum256([]byte("synthetic-multihub-bind\x00" + name + "\x00" + nodeID))
			codeDigest := hex.EncodeToString(code[:])
			if _, err = db.CreatePendingNodeDeviceBinding(nodeID, "Synthetic Node", digest, codeDigest, time.Now().Add(10*time.Minute)); err != nil {
				db.Close()
				return err
			}
			if _, err = db.ConfirmPendingNodeDeviceBinding(ownerID, deviceID, codeDigest); err != nil {
				db.Close()
				return err
			}
			if foreign == 1 {
				entry.ForeignOwnerToken = token
				continue
			}
			entry.Token = token
			hubState := machineHubStateDir(writerRoot, config)
			if err = persistMachineNodeIdentity(filepath.Join(machineNodeStateDir(hubState, nodeID), "identity.json"), machineNodeCredentialPath(hubState, nodeID), &machineNodeIdentity{Version: 1, NodeID: nodeID, RelayToken: token}); err != nil {
				db.Close()
				return err
			}
			crypto, makeErr := nodekeys.OpenCryptoState(machineNodeStateDir(hubState, nodeID))
			if makeErr != nil {
				db.Close()
				return makeErr
			}
			fp, makeErr := nodekeys.PeerKeyFingerprint(owner.Public())
			if makeErr == nil {
				_, makeErr = crypto.TrustOwnerApprovalKeyLocal(ownerID, key.KeyID, owner.Public(), fp)
			}
			closeErr := crypto.Close()
			if makeErr != nil {
				db.Close()
				return makeErr
			}
			if closeErr != nil {
				db.Close()
				return closeErr
			}
		}
		if err = db.Close(); err != nil {
			return err
		}
		var secret [32]byte
		if _, err = rand.Read(secret[:]); err != nil {
			return err
		}
		entry.ManagerToken = "synthetic-" + hex.EncodeToString(secret[:])
		if err = os.WriteFile(filepath.Join(root, "hubs", name, "env"), []byte("CICADA_API_TOKEN="+entry.ManagerToken+"\n"), 0600); err != nil {
			return err
		}
		entries = append(entries, entry)
		configs = append(configs, config)
	}
	// Initialize the real shared ledgers once; Agents still open and use them.
	admissions, err := nodeinbox.OpenProviderAdmissionLedger(filepath.Join(writerRoot, "node-provider-admission.sqlite3"))
	if err != nil {
		return err
	}
	if err = admissions.Close(); err != nil {
		return err
	}
	contexts, err := nodeinbox.OpenNativeContextRegistry(filepath.Join(writerRoot, "node-native-context-history.sqlite3"))
	if err != nil {
		return err
	}
	if err = contexts.Close(); err != nil {
		return err
	}
	if err = multiHubDockerWrite(filepath.Join(nodeRoot, "proxy.json"), entries); err != nil {
		return err
	}
	if err = multiHubDockerWrite(filepath.Join(nodeRoot, "hubs.json"), machineHubConfigFile{Version: 1, Hubs: configs}); err != nil {
		return err
	}
	public := make([]map[string]string, 0, 2)
	for _, e := range entries {
		public = append(public, map[string]string{"name": e.Name, "hub_id": e.HubID, "owner_id": e.OwnerID, "node_id": e.NodeID, "origin": e.Origin, "state_relative": e.StateRelative})
	}
	return multiHubDockerWrite(filepath.Join(root, "fixture-public.json"), public)
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
				return nil
			}
			update(e.Name, func(m *multiHubDockerMetric) {
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
		server := &http.Server{Addr: u.Host, Handler: proxy, ReadHeaderTimeout: 5 * time.Second}
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
