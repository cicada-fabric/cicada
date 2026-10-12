//go:build linux && amd64 && cgo && cicada_pqtls

package main

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"log"
	"math/big"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/cicada-ai/cicada/internal/clientwire"
	"github.com/cicada-ai/cicada/internal/e2ee"
	"github.com/cicada-ai/cicada/internal/fabric"
	"github.com/cicada-ai/cicada/internal/nodekeys"
	"github.com/cicada-ai/cicada/internal/nodetransport"
	"github.com/cicada-ai/cicada/internal/pqtls"
	"github.com/cicada-ai/cicada/internal/store"
)

// This optional gate starts an empty product Hub and obtains actual encrypted
// Client approvals before invoking the product operator commands. No legacy
// approved Store fixture is copied or promoted into a first deployment.
func TestIPFirstInstallOperatorCLI(t *testing.T) {
	binary := os.Getenv("CICADA_IP_TEST_BINARY")
	if binary == "" {
		t.Skip("explicit first-install artifact gate is OFF")
	}
	lifetime := 150 * time.Second
	if os.Getenv("CICADA_IP_TEST_COMMAND_DIR") != "" {
		lifetime = 300 * time.Second
	}
	ctx, cancel := context.WithTimeout(context.Background(), lifetime)
	defer cancel()
	root, err := os.MkdirTemp(os.Getenv("PQTLS_TEST_ARTIFACT_DIR"), "synthetic-ip-first-install-")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(root)
	for _, dir := range []string{"hub-state", "owner-signer", "transfers", "node-a", "node-b", "ca", "trust"} {
		if err := os.Mkdir(filepath.Join(root, dir), 0700); err != nil {
			t.Fatal(err)
		}
	}
	hubState := filepath.Join(root, "hub-state")
	dbPath := filepath.Join(hubState, "cicada.sqlite3")
	frontAddress, pqAddress := productFreeAddress(t), productFreeAddress(t)
	_, frontPort, _ := net.SplitHostPort(frontAddress)
	origin, bootstrapTransport, bootstrapRoot, closeBootstrap := firstInstallHTTPSFrontend(t, root, "http://"+frontAddress)
	defer closeBootstrap()
	environment := distributionProcessEnvironment("CICADA_STATE_DIR="+hubState, "CICADA_WORKSPACE_ROOT="+filepath.Join(root, "workspace"), "CICADA_API_TOKEN=synthetic-first-install-only")
	environment = append(environment, "SSL_CERT_FILE="+bootstrapRoot)
	if libraries := os.Getenv("CICADA_IP_TEST_PRODUCT_LIBRARY_PATH"); libraries != "" {
		environment = append(environment, "LD_LIBRARY_PATH="+libraries, "OPENSSL_CONF=/dev/null")
	}
	var externalSequence int
	run := func(expectSuccess bool, args ...string) []byte {
		t.Helper()
		var data []byte
		var err error
		nodeState := ""
		for i, arg := range args {
			if arg == "--state-dir" && i+1 < len(args) {
				nodeState = args[i+1]
			}
		}
		if commandDir := os.Getenv("CICADA_IP_TEST_COMMAND_DIR"); commandDir != "" && nodeState != "" {
			externalSequence++
			req := map[string]any{"sequence": externalSequence, "target": filepath.Base(nodeState), "state_root": nodeState, "transfer_root": filepath.Join(root, "transfers"), "trust_root": filepath.Join(root, "trust"), "bootstrap_root": bootstrapRoot, "pq_root": filepath.Join(root, "trust", "root.pem"), "owner_public": filepath.Join(root, "owner-signer", "public.json"), "args": args}
			path := filepath.Join(commandDir, fmt.Sprintf("%04d.request.json", externalSequence))
			encoded, _ := json.Marshal(req)
			runtimeStartupWrite(t, path+".tmp", encoded)
			if err := os.Rename(path+".tmp", path); err != nil {
				t.Fatal(err)
			}
			for i := 0; i < 600; i++ {
				body, readErr := os.ReadFile(path + ".response.json")
				if readErr == nil {
					var response struct {
						Exit   int    `json:"exit"`
						Output []byte `json:"output"`
					}
					if json.Unmarshal(body, &response) != nil {
						t.Fatal("external command receipt malformed")
					}
					data = response.Output
					if response.Exit != 0 {
						err = fmt.Errorf("external Node exit=%d", response.Exit)
					}
					break
				}
				if ctx.Err() != nil {
					t.Fatal("external Node command deadline")
				}
				time.Sleep(50 * time.Millisecond)
				if i == 599 {
					t.Fatal("external Node command timeout")
				}
			}
		} else {
			command := exec.CommandContext(ctx, binary, args...)
			command.Env = environment
			data, err = command.CombinedOutput()
		}
		if (err == nil) != expectSuccess {
			if len(args) > 0 && args[0] == "tls-provision" {
				t.Logf("operator_error=%s", strings.TrimSpace(string(data)))
			}
			if expectSuccess && len(data) <= 1024 && !bytes.ContainsAny(data, "{}") && !bytes.Contains(data, []byte("PRIVATE")) {
				t.Logf("product_error=%s", strings.TrimSpace(string(data)))
			}
			t.Fatalf("product command phase=%s success=%t error=%v transcript_sha256=%s", strings.Join(args[:min(len(args), 2)], "-"), expectSuccess, err, e2ee.NodeTLSAuthorityDigest(data))
		}
		return data
	}
	var hub *exec.Cmd
	var hubOutput distributionOutput
	stopHub := func() {
		t.Helper()
		if hub == nil {
			return
		}
		_ = hub.Process.Signal(os.Interrupt)
		done := make(chan error, 1)
		go func() { done <- hub.Wait() }()
		select {
		case err := <-done:
			if err != nil {
				t.Errorf("product Hub exit: %v", err)
			}
		case <-time.After(12 * time.Second):
			_ = hub.Process.Kill()
			<-done
			t.Error("Hub did not stop")
		}
		hub = nil
	}
	defer stopHub()
	startHub := func(fabricOnly bool, config string) {
		t.Helper()
		args := []string{"serve", "--host", "127.0.0.1", "--port", frontPort}
		if fabricOnly {
			args = append(args, "--fabric-only")
		}
		if config != "" {
			args = append(args, "--node-pqtls-config", config)
		}
		hub = exec.CommandContext(ctx, binary, args...)
		hub.Env = environment
		hub.Stdout = &hubOutput
		hub.Stderr = &hubOutput
		if err := hub.Start(); err != nil {
			t.Fatal(err)
		}
		for i := 0; i < 100; i++ {
			response, err := (&http.Client{Timeout: 200 * time.Millisecond, Transport: bootstrapTransport}).Get(origin + "/healthz")
			if err == nil {
				response.Body.Close()
				if response.StatusCode == 200 {
					return
				}
			}
			time.Sleep(30 * time.Millisecond)
		}
		t.Fatal("fresh product Hub readiness timeout")
	}
	request := func(method, path string, body []byte, want int) []byte {
		t.Helper()
		req, err := http.NewRequestWithContext(ctx, method, origin+path, bytes.NewReader(body))
		if err != nil {
			t.Fatal(err)
		}
		req.Header.Set("Content-Type", "application/json")
		response, err := (&http.Client{Timeout: 10 * time.Second, Transport: bootstrapTransport}).Do(req)
		if err != nil {
			t.Fatal(err)
		}
		defer response.Body.Close()
		data, err := io.ReadAll(io.LimitReader(response.Body, 1<<20))
		if err != nil || response.StatusCode != want {
			t.Fatalf("fresh protocol path=%s status=%d want=%d error=%v transcript_sha256=%s", path, response.StatusCode, want, err, e2ee.NodeTLSAuthorityDigest(data))
		}
		return data
	}
	writeJSON := func(name string, value any) string {
		t.Helper()
		path := filepath.Join(root, "transfers", name)
		data, err := json.Marshal(value)
		if err != nil {
			t.Fatal(err)
		}
		runtimeStartupWrite(t, path, data)
		return path
	}
	startHub(false, "")
	var hubIdentity struct {
		HubID                 string              `json:"hub_id"`
		ControlPublicIdentity e2ee.PublicIdentity `json:"control_public_identity"`
	}
	if json.Unmarshal(request("GET", "/v2/client/identity", nil, 200), &hubIdentity) != nil || hubIdentity.HubID == "" {
		t.Fatal("fresh Hub identity missing")
	}
	stopHub()
	ownerPrivate, ownerPublic := filepath.Join(root, "owner-signer", "private.json"), filepath.Join(root, "owner-signer", "public.json")
	run(true, "owner-key", "generate", "--private", ownerPrivate, "--public", ownerPublic)
	ownerBytes, err := os.ReadFile(ownerPrivate)
	if err != nil {
		t.Fatal(err)
	}
	owner, err := e2ee.UnmarshalIdentity(ownerBytes)
	clear(ownerBytes)
	if err != nil {
		t.Fatal(err)
	}
	ownerID := hubIdentity.ControlPublicIdentity.ID
	run(true, "owner-key", "register", "--db", dbPath, "--owner-id", ownerID, "--public", ownerPublic, "--expect-key-id", owner.Public().ID)
	startHub(false, "")
	device, err := e2ee.NewIdentity()
	if err != nil {
		t.Fatal(err)
	}
	deviceID := "SYNTHETIC-first-install-device"
	grant, err := owner.SignOwnerDeviceGrant(ownerID, deviceID, device.Public(), hubIdentity.HubID, e2ee.OwnerDevicePurposeControl, time.Now().Add(-time.Minute), time.Now().Add(time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	enrollment, _ := json.Marshal(map[string]any{"owner_id": ownerID, "owner_key_id": owner.Public().ID, "device_id": deviceID, "device_public_identity": device.Public(), "owner_device_grant": grant})
	var enrolled struct {
		SessionEpoch     uint64 `json:"session_epoch"`
		DeviceKeyVersion uint64 `json:"device_key_version"`
		State            string `json:"state"`
	}
	if json.Unmarshal(request("POST", "/v2/client/devices/enroll", enrollment, 201), &enrolled) != nil || enrolled.State != "ACTIVE" {
		t.Fatal("actual Client device enrollment failed")
	}
	clientBinding := clientwire.Binding{HubID: hubIdentity.HubID, OwnerID: ownerID, DeviceID: deviceID, SessionEpoch: enrolled.SessionEpoch, HubKeyVersion: 1, DeviceKeyVersion: enrolled.DeviceKeyVersion}
	var sequence uint64
	ownerRPC := func(operation string, input any, target any) {
		t.Helper()
		sequence++
		body, _ := json.Marshal(input)
		route := clientwire.Route{Version: 1, Direction: clientwire.DirectionRequest, HubID: hubIdentity.HubID, OwnerID: ownerID, DeviceID: deviceID, SessionEpoch: enrolled.SessionEpoch, Sequence: sequence, OperationID: fmt.Sprintf("synthetic-first-install-%d", sequence), Operation: operation, SenderKeyID: device.Public().ID, SenderKeyVersion: enrolled.DeviceKeyVersion, ReceiverKeyID: hubIdentity.ControlPublicIdentity.ID, ReceiverKeyVersion: 1}
		packet, err := clientwire.SealRequest(device, hubIdentity.ControlPublicIdentity, clientBinding, route, body)
		if err != nil {
			t.Fatal(err)
		}
		response := request("POST", "/v2/client/rpc", packet, 200)
		opened, err := clientwire.OpenResponse(device, hubIdentity.ControlPublicIdentity, clientBinding, response)
		if err != nil {
			t.Fatal(err)
		}
		var envelope struct {
			OK     bool            `json:"ok"`
			Result json.RawMessage `json:"result"`
		}
		if json.Unmarshal(opened.Plaintext, &envelope) != nil || !envelope.OK {
			t.Fatal("encrypted Owner operation rejected", operation)
		}
		if err := json.Unmarshal(envelope.Result, target); err != nil {
			t.Fatal(err)
		}
	}
	states := map[string]string{}
	originForNode := func(nodeID string) string {
		if nodeID == "synthetic-node-b" && os.Getenv("CICADA_IP_TEST_HUB_IP_B") != "" {
			u, _ := url.Parse(origin)
			u.Host = net.JoinHostPort(os.Getenv("CICADA_IP_TEST_HUB_IP_B"), u.Port())
			return u.String()
		}
		return origin
	}
	for _, nodeID := range []string{"synthetic-node-a", "synthetic-node-b"} {
		state := filepath.Join(root, strings.TrimPrefix(nodeID, "synthetic-"))
		states[nodeID] = state
		run(false, "machine", "agent", "--id", nodeID, "--state-dir", state, "--control-url", originForNode(nodeID), "--once")
		var local machineNodeControlState
		_, statePath := machineNodeControlPaths(state, nodeID)
		data, err := os.ReadFile(statePath)
		if err != nil || json.Unmarshal(data, &local) != nil || local.PendingPairing == nil {
			t.Fatal("fresh Node failed to retain pending pairing")
		}
		var preview store.NodeControlKeyCandidate
		ownerRPC("nodes.preview", map[string]any{"user_code": local.PendingPairingUserCode}, &preview)
		if preview.State != store.NodeControlPairingPending {
			t.Fatal("fresh Node was approved without Owner decision")
		}
		// The new provisioning command cannot manufacture a local binding while pending.
		run(false, "tls-provision", "node-binding-request", "--state-dir", state, "--node-id", nodeID, "--hub-id", hubIdentity.HubID, "--origin", originForNode(nodeID), "--output", filepath.Join(root, "transfers", nodeID+"-pending"))
		var confirmed store.NodeControlKeyBinding
		ownerRPC("nodes.confirm", map[string]any{"user_code": local.PendingPairingUserCode, "candidate_digest": preview.CandidateDigest, "candidate_version": preview.Version}, &confirmed)
		if confirmed.State != "ACTIVE" {
			t.Fatal("exact encrypted Owner candidate confirmation failed")
		}
		run(true, "machine", "agent", "--id", nodeID, "--state-dir", state, "--control-url", originForNode(nodeID), "--once")
		fingerprint, err := nodekeys.PeerKeyFingerprint(owner.Public())
		if err != nil {
			t.Fatal(err)
		}
		run(true, "machine", "trust-owner-key", "--id", nodeID, "--state-dir", state, "--owner-id", ownerID, "--public", ownerPublic, "--expect-key-id", owner.Public().ID, "--expect-fingerprint", fingerprint)
	}
	stopHub()
	chain, rootPEM, issuerSecret, at := runtimeStartupCA(t, filepath.Join(root, "ca"))
	runtimeStartupWrite(t, filepath.Join(root, "trust", "root.pem"), rootPEM)
	defer clear(issuerSecret)
	issuer, profile, err := pqtls.ImportTLSIssuer(chain, issuerSecret, rootPEM, "node", at)
	if err != nil {
		t.Fatal(err)
	}
	issuer.Destroy()
	hubIssuer, _, err := pqtls.ImportTLSIssuer(chain, issuerSecret, rootPEM, "hub", at)
	if err != nil {
		t.Fatal(err)
	}
	defer hubIssuer.Destroy()
	hubTLSKey, csr, err := pqtls.GenerateTLSCSR(pqtls.TLSCSRParameters{Role: "hub", DNSName: "hub.synthetic.invalid"})
	if err != nil {
		t.Fatal(err)
	}
	defer hubTLSKey.Destroy()
	params := pqtls.TLSLeafParameters{TLSCSRParameters: csr.Parameters, ExpectedSPKIHash: csr.SPKIDERHash, NotBefore: at, NotAfter: at.Add(time.Hour)}
	params.Serial[15] = 99
	hubLeaf, err := hubIssuer.IssueTLSLeaf(csr.CSRPEM, params, at)
	if err != nil {
		t.Fatal(err)
	}
	hubSecret, err := hubTLSKey.ExportPEM()
	if err != nil {
		t.Fatal(err)
	}
	runtimeStartupWrite(t, filepath.Join(root, "ca", "hub.key"), hubSecret)
	clear(hubSecret)
	runtimeStartupWrite(t, filepath.Join(root, "ca", "hub-chain.pem"), append(append([]byte(nil), hubLeaf.CertificatePEM...), chain...))
	runtimeStartupWrite(t, filepath.Join(root, "ca", "issuer-chain.pem"), chain)
	_, pqPort, _ := net.SplitHostPort(pqAddress)
	if os.Getenv("CICADA_IP_TEST_HUB_IP_A") != "" {
		pqAddress = net.JoinHostPort("0.0.0.0", pqPort)
	}
	dialForNode := func(nodeID string) string {
		ip := os.Getenv("CICADA_IP_TEST_HUB_IP_A")
		if nodeID == "synthetic-node-b" {
			ip = os.Getenv("CICADA_IP_TEST_HUB_IP_B")
		}
		if ip != "" {
			return net.JoinHostPort(ip, pqPort)
		}
		return pqAddress
	}
	pqOrigin := "https://hub.synthetic.invalid:" + pqPort
	hash := func(value [32]byte) string { return hex.EncodeToString(value[:]) }
	hubConfig := nodetransport.Config{Version: 1, Role: "hub", Listen: pqAddress, CertificateFile: filepath.Join(root, "ca", "hub-chain.pem"), PrivateKeyFile: filepath.Join(root, "ca", "hub.key"), TrustFile: filepath.Join(root, "ca", "root.pem"), Identity: nodetransport.Identity{Kind: "hub", HubID: hubIdentity.HubID, DNSName: "hub.synthetic.invalid"}}
	activeFiles := map[string]string{}
	for _, nodeID := range []string{"synthetic-node-a", "synthetic-node-b"} {
		state := states[nodeID]
		name := strings.TrimPrefix(nodeID, "synthetic-")
		requestID := "SYNTHETIC-FIRST-" + nodeID
		coordinates := []string{"--state-dir", state, "--node-id", nodeID, "--hub-id", hubIdentity.HubID, "--origin", originForNode(nodeID)}
		phase := func(name string, args ...string) {
			t.Helper()
			run(true, append(append([]string{"tls-provision", name}, coordinates...), args...)...)
		}
		challenge := filepath.Join(root, "transfers", nodeID+"-challenge")
		phase("node-binding-request", "--output", challenge)
		bindingFile := filepath.Join(root, "transfers", nodeID+"-binding")
		run(true, "tls-provision", "hub-binding-export", "--db", dbPath, "--input", challenge, "--hub-key", filepath.Join(hubState, "e2ee", "node-control-identity.json"), "--output", bindingFile)
		prepRequest := nodetransport.TLSPreparationRequest{RequestID: requestID, DNSName: name + ".synthetic.invalid", HubDNSName: "hub.synthetic.invalid", HubPQOrigin: pqOrigin, HubDialAddress: dialForNode(nodeID), ApplicationOrigin: originForNode(nodeID), HubSPKIHash: hash(csr.SPKIDERHash), HubTrustAnchorDERHash: hash(profile.TrustAnchorDERHash), IssuerGeneration: "SYNTHETIC-first-install-only", IssuerSPKIHash: hash(profile.SPKIDERHash), IssuerDERHash: hash(profile.CertificateDERHash), RootDERHash: hash(profile.TrustAnchorDERHash)}
		prepInput := writeJSON(nodeID+"-prep-input", prepRequest)
		prepOutput := filepath.Join(root, "transfers", nodeID+"-prepared")
		phase("node-prepare", "--input", bindingFile, "--challenge", challenge, "--preparation", prepInput, "--output", prepOutput)
		replayedRequest := prepRequest
		replayedRequest.RequestID += "-replayed-nonce"
		replayedInput := writeJSON(nodeID+"-replayed-prepare", replayedRequest)
		run(false, append(append([]string{"tls-provision", "node-prepare"}, coordinates...), "--input", bindingFile, "--challenge", challenge, "--preparation", replayedInput, "--output", filepath.Join(root, "transfers", nodeID+"-replayed-output"))...)
		var prepared nodetransport.TLSPreparedCandidate
		data, _ := os.ReadFile(prepOutput)
		if json.Unmarshal(data, &prepared) != nil {
			t.Fatal("product CSR output malformed")
		}
		_, token, err := loadMachineRecoveryClient(state, nodeID)
		if err != nil {
			t.Fatal(err)
		}
		reservedAt := time.Now().UTC().Truncate(time.Second)
		candidate := store.NodeTLSCandidateInput{RequestID: requestID, NodeID: nodeID, CredentialDigest: fabric.HashSessionCredential(token), CSRPEM: prepared.CSRPEM, IssuerChainPEM: chain, TrustAnchorPEM: rootPEM, Parameters: pqtls.TLSCSRParameters{Role: "node", DNSName: prepRequest.DNSName}, Issuer: profile, IssuerGeneration: prepRequest.IssuerGeneration, NotBefore: reservedAt, NotAfter: at.Add(time.Hour), ExpectedTLSEpochFloor: prepared.LocalAcceptedTLSEpochFloor, HubSPKIHash: prepRequest.HubSPKIHash, HubTrustAnchorDERHash: prepRequest.HubTrustAnchorDERHash, HubPQOrigin: pqOrigin, HubDialAddress: dialForNode(nodeID), ApplicationOrigin: originForNode(nodeID), GrantIssuedAt: reservedAt, GrantExpiresAt: at.Add(time.Hour), GrantNonce: e2ee.NodeTLSAuthorityDigest([]byte("SYNTHETIC first TLS " + nodeID))}
		candidateFile := writeJSON(nodeID+"-candidate", candidate)
		reservedFile := filepath.Join(root, "transfers", nodeID+"-reserved")
		run(true, "tls-provision", "hub-reserve", "--db", dbPath, "--input", candidateFile, "--output", reservedFile)
		var reserved store.NodeTLSAuthoritySnapshot
		data, _ = os.ReadFile(reservedFile)
		json.Unmarshal(data, &reserved)
		claimsFile := writeJSON(nodeID+"-claims", reserved.Claims)
		claimsBytes, _ := os.ReadFile(claimsFile)
		proofFile := filepath.Join(root, "owner-signer", nodeID+"-tls-proof")
		run(true, "owner", "tls-leaf-grant-sign", "--private", ownerPrivate, "--claims", claimsFile, "--expect-claims-sha256", e2ee.NodeTLSAuthorityDigest(claimsBytes), "--expect-owner-id", ownerID, "--expect-owner-key-id", owner.Public().ID, "--expect-hub-id", hubIdentity.HubID, "--expect-node-id", nodeID, "--output", proofFile)
		action := store.NodeTLSAuthorityActionInput{RequestID: requestID, NodeID: nodeID, CredentialDigest: candidate.CredentialDigest, ExpectedVersion: reserved.RowVersion}
		actionFile := writeJSON(nodeID+"-issue-action", action)
		signedFile := filepath.Join(root, "transfers", nodeID+"-signed")
		run(true, "tls-provision", "hub-issue", "--db", dbPath, "--input", actionFile, "--grant", proofFile, "--issuer-chain", filepath.Join(root, "ca", "issuer-chain.pem"), "--issuer-key", filepath.Join(root, "ca", "issuer.key"), "--root", filepath.Join(root, "ca", "root.pem"), "--output", signedFile)
		ackFile := filepath.Join(root, "transfers", nodeID+"-ack")
		phase("node-stage", "--request-id", requestID, "--input", signedFile, "--hub-trust", filepath.Join(root, "trust", "root.pem"), "--output", ackFile)
		var signed store.NodeTLSAuthoritySnapshot
		data, _ = os.ReadFile(signedFile)
		json.Unmarshal(data, &signed)
		action.ExpectedVersion = signed.RowVersion
		actionFile = writeJSON(nodeID+"-ack-action", action)
		installedFile := filepath.Join(root, "transfers", nodeID+"-installed")
		run(true, "tls-provision", "hub-ack", "--db", dbPath, "--input", actionFile, "--ack", ackFile, "--output", installedFile)
		var installed store.NodeTLSAuthoritySnapshot
		data, _ = os.ReadFile(installedFile)
		json.Unmarshal(data, &installed)
		action.ExpectedVersion = installed.RowVersion
		actionFile = writeJSON(nodeID+"-activate-action", action)
		activeFile := filepath.Join(root, "transfers", nodeID+"-active")
		run(true, "tls-provision", "hub-activate", "--db", dbPath, "--input", actionFile, "--hub-key", filepath.Join(hubState, "e2ee", "node-control-identity.json"), "--output", activeFile)
		activeFiles[nodeID] = activeFile
		var active store.NodeTLSAuthoritySnapshot
		data, _ = os.ReadFile(activeFile)
		json.Unmarshal(data, &active)
		hubConfig.Peers = append(hubConfig.Peers, nodetransport.Approval{Identity: nodetransport.Identity{Kind: "node", HubID: hubIdentity.HubID, NodeID: nodeID, TLSEpoch: active.Claims.TLSEpoch, DNSName: active.Claims.DNSName}, PinKind: "spki-sha256", PinSHA256: active.Claims.SPKIDERHash, OwnerID: ownerID, OwnerKeyID: active.Claims.OwnerKeyID, BindingID: active.Claims.OwnerBindingID, BindingVersion: int64(active.Claims.OwnerBindingVersion), CredentialVersion: int64(active.Claims.CredentialVersion)})
		// ACTIVE labels/receipts cannot satisfy Apply while the real Hub is offline.
		phaseArgs := append(append([]string{"tls-provision", "node-apply"}, coordinates...), "--request-id", requestID, "--input", activeFile, "--output", filepath.Join(root, "transfers", nodeID+"-offline-apply"))
		run(false, phaseArgs...)
	}
	hubConfigFile := writeJSON("hub-pqtls.json", hubConfig)
	startHub(true, hubConfigFile)
	for _, nodeID := range []string{"synthetic-node-a", "synthetic-node-b"} {
		state := states[nodeID]
		run(true, "tls-provision", "node-apply", "--state-dir", state, "--node-id", nodeID, "--hub-id", hubIdentity.HubID, "--origin", originForNode(nodeID), "--request-id", "SYNTHETIC-FIRST-"+nodeID, "--input", activeFiles[nodeID], "--output", filepath.Join(root, "transfers", nodeID+"-applied"))
		activePath := filepath.Join(state, ".node-tls", e2ee.NodeTLSAuthorityDigest([]byte(hubIdentity.HubID+"\x00"+nodeID)), "active.json")
		h := &machineHubContext{StateDir: state, WriterRoot: state, NodeID: nodeID, HubID: hubIdentity.HubID, Origin: originForNode(nodeID)}
		if _, err := nodetransport.ReadAcceptedTLSRuntimeBinding(state, state, hubIdentity.HubID, nodeID); err != nil {
			t.Fatal("first-install diagnostic accepted-binding", err)
		}
		if _, _, _, err := machineTLSExistingBinding(h); err != nil {
			t.Fatal("first-install diagnostic existing-binding", err)
		}
		if local, closeLocal, err := machineTLSOpenLocal(h); err != nil {
			t.Fatal("first-install diagnostic local-trust", err)
		} else {
			_ = local
			closeLocal()
		}
		if err := configureMachinePQTransport(h, activePath); err != nil {
			t.Fatal("first-install diagnostic checked-runtime", err)
		}
		h.TLSRuntime.Close()
		wrong := &machineHubContext{StateDir: state, WriterRoot: state, NodeID: nodeID, HubID: "synthetic-explicit-wrong-hub", Origin: originForNode(nodeID)}
		if err := recoverMachinePQHubIdentityHint(wrong, activePath); err != nil || wrong.HubID != "synthetic-explicit-wrong-hub" {
			t.Fatal("explicit Hub pin was overwritten")
		}
		if err := configureMachinePQTransport(wrong, activePath); err == nil {
			wrong.TLSRuntime.Close()
			t.Fatal("explicit wrong Hub pin admitted")
		}
		run(true, "machine", "agent", "--relay-only", "--once", "--id", nodeID, "--state-dir", state, "--control-url", originForNode(nodeID), "--pqtls-config", activePath)
	}
	stopHub()
	startHub(true, hubConfigFile)
	for _, nodeID := range []string{"synthetic-node-a", "synthetic-node-b"} {
		state := states[nodeID]
		activePath := filepath.Join(state, ".node-tls", e2ee.NodeTLSAuthorityDigest([]byte(hubIdentity.HubID+"\x00"+nodeID)), "active.json")
		run(true, "machine", "agent", "--relay-only", "--once", "--id", nodeID, "--state-dir", state, "--control-url", originForNode(nodeID), "--pqtls-config", activePath)
	}
	// The sender is a fixture caller of the production Runtime/Relay API. The
	// receiver below is the actual product Node, including the ARM64 binary when
	// selected by the host driver. No synthetic native consumer is installed.
	stopHub()
	peerFixture := firstInstallPreparePeer(t, dbPath, ownerID, owner, states)
	startHub(true, hubConfigFile)
	sourceContext, closeSource := firstInstallPeerContext(t, states["synthetic-node-a"], "synthetic-node-a", hubIdentity.HubID, originForNode("synthetic-node-a"))
	ciphertext := firstInstallPeerSend(t, peerFixture, sourceContext, originForNode("synthetic-node-a"), "synthetic-node-a")
	closeSource()
	stopHub()
	firstInstallPeerEvidence(t, dbPath, states["synthetic-node-b"], false, ciphertext)
	startHub(true, hubConfigFile)
	targetState := states["synthetic-node-b"]
	targetActive := filepath.Join(targetState, ".node-tls", e2ee.NodeTLSAuthorityDigest([]byte(hubIdentity.HubID+"\x00synthetic-node-b")), "active.json")
	run(false, "machine", "agent", "--relay-only", "--once", "--id", "synthetic-node-b", "--state-dir", targetState, "--control-url", originForNode("synthetic-node-b"), "--pqtls-config", targetActive)
	stopHub()
	ack := firstInstallPeerEvidence(t, dbPath, targetState, true, ciphertext)
	startHub(true, hubConfigFile)
	targetContext, closeTarget := firstInstallPeerContext(t, targetState, "synthetic-node-b", hubIdentity.HubID, originForNode("synthetic-node-b"))
	wrongACK := *ack
	wrongACK.BindingEpoch++
	if err := machineAPIJSON(targetContext, originForNode("synthetic-node-b")+"/v2/relay/nodes/synthetic-node-b/receipts", http.MethodPost, wrongACK, nil); !machineAPIHasStatus(err, http.StatusBadRequest, http.StatusForbidden, http.StatusUnauthorized, http.StatusNotFound, http.StatusConflict) {
		t.Fatal("wrong-epoch Node ACK was not rejected by HTTP Guard", err)
	}
	for i := 0; i < 2; i++ {
		if err := machineAPIJSON(targetContext, originForNode("synthetic-node-b")+"/v2/relay/nodes/synthetic-node-b/receipts", http.MethodPost, ack, nil); err != nil {
			t.Fatal("exact Node receipt retry rejected", err)
		}
	}
	closeTarget()
	stopHub()
	firstInstallPeerEvidence(t, dbPath, targetState, true, ciphertext)
	t.Log("phase=actual-product-receiver-inbox-node-ack-ciphertext-offline-hub-restart-retry-dedup-native-not-run")
	t.Log("phase=fresh-product-enrollment-independent-owner-first-install-remote-apply-restart")
}

// A throwaway standard HTTPS IP-SAN frontend is only the pre-enrollment
// channel. It is independently trusted through a container-local root file;
// its curve/certificate do not count as the enrolled pure-PQ transport.
func firstInstallHTTPSFrontend(t *testing.T, root, target string) (string, *http.Transport, string, func()) {
	t.Helper()
	at := time.Now().UTC()
	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	caTemplate := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "CICADA SYNTHETIC BOOTSTRAP CA TEST ONLY"}, NotBefore: at.Add(-time.Minute), NotAfter: at.Add(time.Hour), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageCRLSign}
	caDER, err := x509.CreateCertificate(rand.Reader, caTemplate, caTemplate, &caKey.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	ca, err := x509.ParseCertificate(caDER)
	if err != nil {
		t.Fatal(err)
	}
	leafKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	leafTemplate := &x509.Certificate{SerialNumber: big.NewInt(2), Subject: pkix.Name{CommonName: "CICADA SYNTHETIC IP BOOTSTRAP TEST ONLY"}, NotBefore: at.Add(-time.Minute), NotAfter: at.Add(time.Hour), IPAddresses: []net.IP{net.ParseIP("127.0.0.1"), net.ParseIP("::1")}, KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}, BasicConstraintsValid: true}
	for _, name := range []string{"CICADA_IP_TEST_HUB_IP_A", "CICADA_IP_TEST_HUB_IP_B"} {
		if ip := net.ParseIP(os.Getenv(name)); ip != nil {
			leafTemplate.IPAddresses = append(leafTemplate.IPAddresses, ip)
		}
	}
	leafDER, err := x509.CreateCertificate(rand.Reader, leafTemplate, ca, &leafKey.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	keyDER, err := x509.MarshalECPrivateKey(leafKey)
	if err != nil {
		t.Fatal(err)
	}
	rootFile, leafFile, keyFile := filepath.Join(root, "trust", "bootstrap-root.pem"), filepath.Join(root, "ca", "bootstrap-leaf.pem"), filepath.Join(root, "ca", "bootstrap-key.pem")
	runtimeStartupWrite(t, rootFile, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: caDER}))
	runtimeStartupWrite(t, leafFile, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: leafDER}))
	runtimeStartupWrite(t, keyFile, pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER}))
	clear(keyDER)
	u, err := url.Parse(target)
	if err != nil {
		t.Fatal(err)
	}
	proxy := httputil.NewSingleHostReverseProxy(u)
	proxy.Transport = &http.Transport{Proxy: nil}
	proxy.ErrorLog = log.New(io.Discard, "", 0)
	listen := "127.0.0.1:0"
	if os.Getenv("CICADA_IP_TEST_HUB_IP_A") != "" {
		listen = "0.0.0.0:0"
	}
	listener, err := net.Listen("tcp", listen)
	if err != nil {
		t.Fatal(err)
	}
	server := &http.Server{Handler: proxy, ReadHeaderTimeout: 5 * time.Second}
	done := make(chan error, 1)
	go func() { done <- server.ServeTLS(listener, leafFile, keyFile) }()
	roots := x509.NewCertPool()
	roots.AddCert(ca)
	transport := &http.Transport{Proxy: nil, TLSClientConfig: &tls.Config{RootCAs: roots, MinVersion: tls.VersionTLS12}}
	close := func() {
		transport.CloseIdleConnections()
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = server.Shutdown(ctx)
		_ = server.Close()
		<-done
	}
	address := listener.Addr().String()
	if ip := os.Getenv("CICADA_IP_TEST_HUB_IP_A"); ip != "" {
		_, port, _ := net.SplitHostPort(address)
		address = net.JoinHostPort(ip, port)
	}
	return "https://" + address, transport, rootFile, close
}
