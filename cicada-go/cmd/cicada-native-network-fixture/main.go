// Test-only operator for an owned disposable native Network/Monitor gate.
// Private Owner/device signers never enter the Node or Hub mount namespaces.
package main

import (
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"syscall"
	"time"

	"github.com/cicada-ai/cicada/internal/clientwire"
	"github.com/cicada-ai/cicada/internal/e2ee"
	"github.com/cicada-ai/cicada/internal/fabric"
	"github.com/cicada-ai/cicada/internal/nodekeys"
	"github.com/cicada-ai/cicada/internal/store"
)

type metadata struct {
	HubID      string              `json:"hub_id"`
	OwnerID    string              `json:"owner_id"`
	OwnerKeyID string              `json:"owner_key_id"`
	NetworkID  string              `json:"network_id"`
	NodeID     string              `json:"node_id"`
	DeviceID   string              `json:"device_id"`
	HubPublic  e2ee.PublicIdentity `json:"hub_public"`
}

func main() {
	if err := run(os.Args[1:]); err != nil {
		fmt.Fprintln(os.Stderr, "native Network fixture:", err)
		os.Exit(1)
	}
}
func write(path string, value []byte) error {
	file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		return err
	}
	defer file.Close()
	if _, err = file.Write(value); err != nil {
		return err
	}
	return file.Sync()
}
func save(path string, value any) error {
	data, err := json.MarshalIndent(value, "", "  ")
	if err != nil {
		return err
	}
	return write(path, append(data, '\n'))
}
func private(path string) ([]byte, error) {
	info, err := os.Lstat(path)
	if err != nil {
		return nil, err
	}
	owner, ok := info.Sys().(*syscall.Stat_t)
	if !info.Mode().IsRegular() || info.Mode().Perm() != 0600 || !ok || owner.Uid != uint32(os.Geteuid()) {
		return nil, errors.New("private file ownership/mode rejected")
	}
	return os.ReadFile(path)
}
func validate(root string) error {
	info, err := os.Lstat(root)
	if err != nil {
		return err
	}
	owner, ok := info.Sys().(*syscall.Stat_t)
	if !filepath.IsAbs(root) || !info.IsDir() || info.Mode().Perm() != 0700 || !ok || owner.Uid != uint32(os.Geteuid()) {
		return errors.New("owned absolute private fixture root required")
	}
	marker, err := private(filepath.Join(root, ".native-network-owned"))
	if err != nil || !strings.HasPrefix(string(marker), "cicada.native-network.disposable.v1\n") {
		return errors.New("disposable ownership marker required")
	}
	return nil
}
func load(root string) (metadata, error) {
	var m metadata
	data, err := private(filepath.Join(root, "network-fixture.json"))
	if err != nil {
		return m, err
	}
	err = json.Unmarshal(data, &m)
	if err == nil && (m.HubID == "" || m.OwnerID == "" || m.NodeID == "" || m.NetworkID == "") {
		err = errors.New("invalid fixture metadata")
	}
	return m, err
}
func signer(path string) (*e2ee.Identity, error) {
	data, err := private(path)
	if err != nil {
		return nil, err
	}
	return e2ee.UnmarshalIdentity(data)
}
func run(raw []string) error {
	if len(raw) == 0 {
		return errors.New("action required")
	}
	action := raw[0]
	flags := flag.NewFlagSet(action, flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	root := flags.String("fixture", "", "owned fixture root")
	base := flags.String("url", "", "exact loopback Hub URL")
	native := flags.String("native-thread", "", "observed native UUID, or synthetic record in offline preflight")
	scope := flags.String("scope", "", "validated MCP scope hash")
	operation := flags.String("operation", "", "encrypted Owner operation")
	bodyFile := flags.String("body-file", "", "private JSON input")
	if err := flags.Parse(raw[1:]); err != nil || flags.NArg() != 0 {
		return errors.New("invalid fixture arguments")
	}
	if err := validate(*root); err != nil {
		return err
	}
	if action == "bootstrap" {
		return bootstrap(*root)
	}
	m, err := load(*root)
	if err != nil {
		return err
	}
	switch action {
	case "issue":
		if !regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$`).MatchString(*native) || !regexp.MustCompile(`^[0-9a-f]{64}$`).MatchString(*scope) {
			return errors.New("exact UUID and MCP scope hash required")
		}
		s, err := store.New(filepath.Join(*root, "hub-state", "cicada.sqlite3"))
		if err != nil {
			return err
		}
		defer s.Close()
		owner, err := signer(filepath.Join(*root, "operator-private", "owner.key"))
		if err != nil {
			return err
		}
		tokenBytes := make([]byte, 32)
		if _, err = rand.Read(tokenBytes); err != nil {
			return err
		}
		invitation := "synthetic-native-network-" + hex.EncodeToString(tokenBytes)
		expiry := time.Now().UTC().Add(time.Hour)
		grants := []string{"directory.discover", "directory.publish"}
		if err = s.IssueNetworkInvitation(m.NetworkID, m.OwnerID, m.OwnerID, invitation, expiry.Format(time.RFC3339Nano), grants); err != nil {
			return err
		}
		proof, err := owner.SignOwnerNetworkJoinGrant(m.OwnerID, m.HubID, m.NetworkID, m.NodeID, *native, store.NetworkInvitationDigest(invitation), m.OwnerKeyID, grants, true, time.Now().UTC().Add(-time.Minute), expiry)
		if err != nil {
			return err
		}
		dir := filepath.Join(*root, "node-a-mcp", "network-join", "scopes", *scope)
		if err = os.MkdirAll(dir, 0700); err != nil {
			return err
		}
		if err = write(filepath.Join(dir, m.NetworkID+".invitation"), []byte(invitation+"\n")); err != nil {
			return err
		}
		if err = write(filepath.Join(dir, m.NetworkID+".proof.json"), proof); err != nil {
			return err
		}
		fmt.Println(`{"issued":true,"preset":"DIRECTORY","owner_private_mounted_to_node":false}`)
		return nil
	case "rpc":
		return rpc(*root, m, *base, *operation, *bodyFile)
	default:
		return errors.New("unknown fixture action")
	}
}

func bootstrap(root string) error {
	dbPath := filepath.Join(root, "hub-state", "cicada.sqlite3")
	if _, err := os.Lstat(dbPath); !errors.Is(err, os.ErrNotExist) {
		return errors.New("bootstrap refuses existing database")
	}
	for _, dir := range []string{"hub-state/e2ee", "operator-private", "node-a-state", "node-a-mcp/network-join", "node-a-mcp/network-session"} {
		if err := os.MkdirAll(filepath.Join(root, dir), 0700); err != nil {
			return err
		}
	}
	hub, err := e2ee.NewIdentity()
	if err != nil {
		return err
	}
	wire, err := hub.MarshalBinary()
	if err != nil {
		return err
	}
	if err = write(filepath.Join(root, "hub-state/e2ee/identity.json"), wire); err != nil {
		return err
	}
	clientControl, err := e2ee.NewIdentity()
	if err != nil {
		return err
	}
	wire, err = clientControl.MarshalBinary()
	if err != nil {
		return err
	}
	if err = write(filepath.Join(root, "hub-state/e2ee/client-control-identity.json"), wire); err != nil {
		return err
	}
	owner, err := e2ee.NewIdentity()
	if err != nil {
		return err
	}
	device, err := e2ee.NewIdentity()
	if err != nil {
		return err
	}
	for name, key := range map[string]*e2ee.Identity{"owner.key": owner, "device.key": device} {
		wire, err = key.MarshalBinary()
		if err != nil {
			return err
		}
		if err = write(filepath.Join(root, "operator-private", name), wire); err != nil {
			return err
		}
	}
	s, err := store.New(dbPath)
	if err != nil {
		return err
	}
	defer s.Close()
	hubID, err := s.GetClientHubID()
	if err != nil {
		return err
	}
	suffixBytes := make([]byte, 8)
	if _, err = rand.Read(suffixBytes); err != nil {
		return err
	}
	suffix := hex.EncodeToString(suffixBytes)
	m := metadata{HubID: hubID, OwnerID: hub.Public().ID, OwnerKeyID: owner.Public().ID, NodeID: "node_native_monitor_" + suffix, DeviceID: "synthetic_operator_" + suffix, HubPublic: clientControl.Public()}
	if _, err = s.CreatePrincipal(store.Principal{ID: m.OwnerID, Kind: store.PrincipalKindHuman, OwnerID: m.OwnerID, TrustDomainID: m.OwnerID, Name: "Synthetic disposable native Monitor Owner", Status: store.PrincipalStatusActive}); err != nil {
		return err
	}
	if _, err = s.RegisterOwnerApprovalKeyLocal(m.OwnerID, owner.Public()); err != nil {
		return err
	}
	grant, err := owner.SignOwnerDeviceGrant(m.OwnerID, m.DeviceID, device.Public(), hubID, e2ee.OwnerDevicePurposeControl, time.Now().UTC().Add(-time.Minute), time.Now().UTC().Add(time.Hour))
	if err != nil {
		return err
	}
	if _, err = s.RegisterClientDeviceFromOwnerGrant(store.RegisterClientDeviceInput{OwnerID: m.OwnerID, OwnerKeyID: m.OwnerKeyID, DeviceID: m.DeviceID, DevicePublic: device.Public(), OwnerDeviceGrant: grant}); err != nil {
		return err
	}
	network, err := s.CreateNetwork(store.Network{HubID: hubID, OwnerID: m.OwnerID, Name: "Synthetic native Monitor Network", ContextPolicy: ""})
	if err != nil {
		return err
	}
	m.NetworkID = network.ID
	if err = s.ActivateNetworkMode(); err != nil {
		return err
	}
	token, digest, err := fabric.NewNodeCredential()
	if err != nil {
		return err
	}
	code := sha256.Sum256([]byte("synthetic-native-monitor-binding\x00" + m.NodeID))
	codeDigest := hex.EncodeToString(code[:])
	if _, err = s.CreatePendingNodeDeviceBinding(m.NodeID, "Synthetic Monitor Node", digest, codeDigest, time.Now().UTC().Add(10*time.Minute)); err != nil {
		return err
	}
	if _, err = s.ConfirmPendingNodeDeviceBinding(m.OwnerID, m.DeviceID, codeDigest); err != nil {
		return err
	}
	dir := filepath.Join(root, "node-a-state", "nodes", "node-"+m.NodeID)
	if err = os.MkdirAll(dir, 0700); err != nil {
		return err
	}
	if err = save(filepath.Join(dir, "identity.json"), map[string]any{"version": 1, "node_id": m.NodeID}); err != nil {
		return err
	}
	if err = write(filepath.Join(dir, "relay.token"), []byte(token+"\n")); err != nil {
		return err
	}
	crypto, err := nodekeys.OpenCryptoState(dir)
	if err != nil {
		return err
	}
	fingerprint, err := nodekeys.PeerKeyFingerprint(owner.Public())
	if err == nil {
		_, err = crypto.TrustOwnerApprovalKeyLocal(m.OwnerID, m.OwnerKeyID, owner.Public(), fingerprint)
	}
	closeErr := crypto.Close()
	if err != nil {
		return err
	}
	if closeErr != nil {
		return closeErr
	}
	if err = save(filepath.Join(root, "network-fixture.json"), m); err != nil {
		return err
	}
	return save(filepath.Join(root, "operator-private", "sequence.json"), uint64(0))
}
func rpc(root string, m metadata, base, operation, bodyFile string) error {
	u, err := url.Parse(base)
	if err != nil || u.Scheme != "http" || u.Hostname() != "127.0.0.1" || u.Port() == "" || u.Path != "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" {
		return errors.New("Owner RPC requires exact loopback URL")
	}
	switch operation {
	case "session.capabilities", "topology.snapshot", "topology.apply", "topology.endpoint_admission_preview", "topology.regroup_proposal", "nodes.list":
	default:
		return errors.New("test Owner operation is not allowlisted")
	}
	body, err := private(bodyFile)
	if err != nil || !json.Valid(body) || len(body) > 65536 {
		return errors.New("private bounded JSON body required")
	}
	key, err := signer(filepath.Join(root, "operator-private/device.key"))
	if err != nil {
		return err
	}
	seqPath := filepath.Join(root, "operator-private/sequence.json")
	data, err := private(seqPath)
	if err != nil {
		return err
	}
	var seq uint64
	if err = json.Unmarshal(data, &seq); err != nil {
		return err
	}
	seq++
	// Reserve before network I/O. A failed request is terminal for this test.
	data, err = json.Marshal(seq)
	if err != nil {
		return err
	}
	f, err := os.OpenFile(seqPath, os.O_WRONLY|os.O_TRUNC, 0600)
	if err != nil {
		return err
	}
	if _, err = f.Write(data); err != nil {
		f.Close()
		return err
	}
	if err = f.Sync(); err != nil {
		f.Close()
		return err
	}
	f.Close()
	binding := clientwire.Binding{HubID: m.HubID, OwnerID: m.OwnerID, DeviceID: m.DeviceID, SessionEpoch: 1, HubKeyVersion: 1, DeviceKeyVersion: 1}
	route := clientwire.Route{Version: 1, Direction: clientwire.DirectionRequest, HubID: m.HubID, OwnerID: m.OwnerID, DeviceID: m.DeviceID, SessionEpoch: 1, Sequence: seq, OperationID: fmt.Sprintf("native-operator-%d", seq), Operation: operation, SenderKeyID: key.Public().ID, SenderKeyVersion: 1, ReceiverKeyID: m.HubPublic.ID, ReceiverKeyVersion: 1}
	packet, err := clientwire.SealRequest(key, m.HubPublic, binding, route, body)
	if err != nil {
		return err
	}
	client := &http.Client{Timeout: 10 * time.Second, Transport: &http.Transport{Proxy: nil}}
	response, err := client.Post(base+"/v2/client/rpc", "application/json", bytes.NewReader(packet))
	if err != nil {
		return errors.New("encrypted Owner HTTP unavailable")
	}
	defer response.Body.Close()
	wire, err := io.ReadAll(io.LimitReader(response.Body, 262145))
	if err != nil || len(wire) > 262144 || response.StatusCode != 200 {
		return fmt.Errorf("encrypted Owner HTTP status %d", response.StatusCode)
	}
	opened, err := clientwire.OpenResponse(key, m.HubPublic, binding, wire)
	if err != nil {
		return errors.New("Owner response authentication failed")
	}
	var result map[string]any
	if err = json.Unmarshal(opened.Plaintext, &result); err != nil {
		return err
	}
	if result["operation_id"] != route.OperationID {
		return errors.New("Owner response correlation failed")
	}
	fmt.Println(string(opened.Plaintext))
	return nil
}
