package main

import (
	"bytes"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/cicada-ai/cicada/internal/e2ee"
	wire "github.com/cicada-ai/cicada/internal/hubaccountwire"
	"github.com/cicada-ai/cicada/internal/hubauth"
	"github.com/cicada-ai/cicada/internal/hubidentity"
	"github.com/cicada-ai/cicada/internal/hubnodes"
	"github.com/cicada-ai/cicada/internal/hubowner"
	"github.com/cicada-ai/cicada/internal/nodebinding"
	"github.com/cicada-ai/cicada/internal/nodewire"
	"github.com/cicada-ai/cicada/internal/server"
	"github.com/cicada-ai/cicada/internal/store"
)

const hubNodesRelayOnceChild = "CICADA_TEST_HUB_NODES_RELAY_ONCE_CHILD"

func TestHubNodesRelayOnceChild(t *testing.T) {
	if os.Getenv(hubNodesRelayOnceChild) != "1" {
		return
	}
	err := runMachineAgent([]string{"--relay-only", "--once", "--id", "synthetic-n3-offline-approval-node", "--state-dir", os.Getenv("CICADA_TEST_NODE_STATE"), "--control-url", os.Getenv("CICADA_TEST_NODE_ORIGIN")})
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(2)
	}
	os.Exit(0)
}

type hubNodeTraceWriter struct {
	http.ResponseWriter
	status int
}

func (w *hubNodeTraceWriter) Unwrap() http.ResponseWriter { return w.ResponseWriter }
func (w *hubNodeTraceWriter) WriteHeader(status int) {
	w.status = status
	w.ResponseWriter.WriteHeader(status)
}

func TestHubNodesRelayOnceResumesRetainedPendingApprovedWhileOffline(t *testing.T) {
	// This Node-only fixture uses a synthetic local trusted operator. The TCP
	// server integration separately proves the real N2/N3 App authorization.
	root := t.TempDir()
	hubState := filepath.Join(root, "hub")
	nodeState := filepath.Join(root, "node")
	db, err := store.New(filepath.Join(hubState, "cicada.sqlite3"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	tcp := httptest.NewUnstartedServer(nil)
	defer tcp.Close()
	setup, err := db.InitializeHubOwnerLocal("Synthetic relay resume Owner", "http://"+tcp.Listener.Addr().String(), true)
	if err != nil {
		t.Fatal(err)
	}
	ids, err := hubidentity.LoadOrCreate(hubState, "")
	if err != nil {
		t.Fatal(err)
	}
	owner, err := e2ee.NewIdentity()
	if err != nil {
		t.Fatal(err)
	}
	device, err := e2ee.NewIdentity()
	if err != nil {
		t.Fatal(err)
	}
	if _, err = db.RegisterOwnerApprovalKeyLocal(setup.OwnerID, owner.Public()); err != nil {
		t.Fatal(err)
	}
	deviceID := "synthetic-node-resume-operator"
	grant, err := owner.SignOwnerDeviceGrant(setup.OwnerID, deviceID, device.Public(), setup.HubID, e2ee.OwnerDevicePurposeControl, time.Now().UTC(), time.Now().UTC().Add(time.Minute))
	if err != nil {
		t.Fatal(err)
	}
	if _, err = db.RegisterClientDeviceFromOwnerGrant(store.RegisterClientDeviceInput{OwnerID: setup.OwnerID, OwnerKeyID: owner.Public().ID, DeviceID: deviceID, DevicePublic: device.Public(), OwnerDeviceGrant: grant}); err != nil {
		t.Fatal(err)
	}
	ownerService, err := hubowner.NewService(db, ids)
	if err != nil {
		t.Fatal(err)
	}
	account, err := hubauth.NewServiceWithNodeAuthority(db, ids)
	if err != nil {
		t.Fatal(err)
	}
	nodes, err := hubnodes.NewService(db, ids)
	if err != nil {
		t.Fatal(err)
	}
	handler := server.NewHubNodesHandler(ownerService, account, nodes)
	var mu sync.Mutex
	trace := map[string]int{}
	tcp.Config.Handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		tw := &hubNodeTraceWriter{ResponseWriter: w, status: 200}
		handler.ServeHTTP(tw, r)
		mu.Lock()
		trace[r.Method+" "+r.URL.Path] = tw.status
		mu.Unlock()
	})
	tcp.Start()
	run := func() ([]byte, error) {
		cmd := exec.Command(os.Args[0], "-test.run=^TestHubNodesRelayOnceChild$")
		cmd.Env = childTestEnvironment(map[string]string{hubNodesRelayOnceChild: "1", "CICADA_TEST_NODE_STATE": nodeState, "CICADA_TEST_NODE_ORIGIN": tcp.URL, "CICADA_HUB_ID": "", "CICADA_NODE_PQTLS_CONFIG": "", "CICADA_STATE_DIR": nodeState})
		return cmd.CombinedOutput()
	}
	privateOutput, err := run()
	waiting := bytes.Contains(privateOutput, []byte("waiting for explicit Owner approval"))
	clear(privateOutput)
	if err == nil || !waiting {
		t.Fatal("fresh synthetic Node did not retain its explicit approval wait")
	}
	nodeID := "synthetic-n3-offline-approval-node"
	local, err := openMachineNodeControlClient(nodeState, tcp.URL, nodeID)
	if err != nil {
		t.Fatal(err)
	}
	if local.state.PendingPairing == nil || local.bindingReady() {
		t.Fatal("fixture lacks retained unconfirmed local candidate")
	}
	beforeKey := local.identity.Public()
	pending := *local.state.PendingPairing
	code, err := wire.NormalizeAppNodeCode(local.state.PendingPairingUserCode)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = db.ConfirmNodeControlKeyRequest(setup.OwnerID, deviceID, nodebinding.CodeDigest(setup.HubID, code), pending.Version, pending.CandidateDigest, ids.NodeControl.Public().ID, nodewire.IdentityFingerprint(ids.NodeControl.Public())); err != nil {
		t.Fatal(err)
	}
	privateOutput, err = run()
	failureAtDirectClaim := bytes.Contains(privateOutput, []byte("claim Network direct sealed deliveries"))
	clear(privateOutput)
	if err != nil {
		t.Logf("synthetic child exit category network_direct_claim=%t", failureAtDirectClaim)
		mu.Lock()
		for path, status := range trace {
			if status >= 400 {
				t.Logf("synthetic exact HTTP path/status: %s %d", path, status)
			}
		}
		mu.Unlock()
		t.Fatal("actual retained-pending one-shot relay CLI did not finish")
	}
	_, statePath := machineNodeControlPaths(nodeState, nodeID)
	machineNodeControlClients.Delete(statePath)
	after, err := openMachineNodeControlClient(nodeState, tcp.URL, nodeID)
	if err != nil {
		t.Fatal(err)
	}
	if !after.bindingReady() || after.state.PendingPairing != nil || after.state.ApprovedRequestID != pending.RequestID || after.identity.Public().ID != beforeKey.ID {
		t.Fatal("restart did not install same approval with retained Node identity")
	}
	mu.Lock()
	defer mu.Unlock()
	if trace["POST /v2/fabric/node/networks/direct/claim"] != http.StatusOK {
		t.Fatal("normal idle relay reconciliation did not reach exact authenticated Node claim")
	}
	for path := range trace {
		if strings.Contains(path, "/jobs") {
			t.Fatal("relay-only restart called Worker management")
		}
	}
}
