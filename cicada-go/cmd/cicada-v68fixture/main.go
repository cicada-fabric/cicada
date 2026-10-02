// Command cicada-v68fixture provisions a disposable joined-Node Docker gate.
// It is test tooling only: it creates synthetic identities and state beneath
// an explicitly supplied fixture directory and never prints private material.
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
	"net"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"syscall"
	"time"

	"github.com/cicada-ai/cicada/internal/e2ee"
	"github.com/cicada-ai/cicada/internal/fabric"
	"github.com/cicada-ai/cicada/internal/nodekeys"
	"github.com/cicada-ai/cicada/internal/store"
)

type fixture struct {
	Version     int    `json:"version"`
	HubID       string `json:"hub_id"`
	OwnerID     string `json:"owner_id"`
	OwnerKeyID  string `json:"owner_key_id"`
	GroupID     string `json:"group_id"`
	NodeA       string `json:"node_a"`
	NodeB       string `json:"node_b"`
	ThreadA     string `json:"thread_a"`
	ThreadB     string `json:"thread_b"`
	DeviceID    string `json:"device_id"`
	SourceState string `json:"source_state"`
	TargetState string `json:"target_state"`
}

func v68ReplyCorrelationMatches(route store.RelaySealedV1Route, requestID, askMessageID string) bool {
	return requestID != "" && askMessageID != "" && route.Kind == "reply" &&
		route.RequestID == requestID && route.ReplyTo == askMessageID
}

func main() {
	if len(os.Args) < 2 {
		fatal(errors.New("usage: cicada-v68fixture bootstrap|approve|check --db PATH --fixture DIR"))
	}
	var err error
	switch os.Args[1] {
	case "bootstrap":
		err = bootstrap(os.Args[2:])
	case "approve":
		err = approve(os.Args[2:])
	case "check":
		err = check(os.Args[2:])
	case "probe":
		err = probe(os.Args[2:])
	default:
		err = errors.New("usage: cicada-v68fixture bootstrap|approve|check|probe [options]")
	}
	if err != nil {
		fatal(err)
	}
}

func probe(raw []string) error {
	flags := flag.NewFlagSet("cicada-v68fixture probe", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	address := flags.String("address", "", "private fixture TCP address to probe")
	if err := flags.Parse(raw); err != nil || len(flags.Args()) != 0 || strings.TrimSpace(*address) == "" {
		return errors.New("probe requires --address host:port")
	}
	connection, err := net.DialTimeout("tcp", *address, 1500*time.Millisecond)
	if err == nil {
		_ = connection.Close()
		fmt.Println(`{"tcp_reachable":true}`)
		return nil
	}
	var networkError net.Error
	if errors.As(err, &networkError) || errors.Is(err, syscall.ECONNREFUSED) ||
		errors.Is(err, syscall.EHOSTUNREACH) || errors.Is(err, syscall.ENETUNREACH) {
		fmt.Println(`{"tcp_reachable":false}`)
		return nil
	}
	return errors.New("TCP isolation probe could not determine reachability")
}

func fatal(err error) {
	fmt.Fprintln(os.Stderr, err)
	os.Exit(1)
}

func args(action string, raw []string) (string, string, error) {
	flags := flag.NewFlagSet("cicada-v68fixture "+action, flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	dbPath := flags.String("db", "", "fixture Hub SQLite database")
	root := flags.String("fixture", "", "owned mode-0700 fixture root")
	if err := flags.Parse(raw); err != nil || len(flags.Args()) != 0 || *dbPath == "" || *root == "" {
		return "", "", errors.New("--db and --fixture are required")
	}
	return validateOwnedFixturePaths(*dbPath, *root, action == "bootstrap")
}

func validateOwnedFixturePaths(dbPath, fixtureRoot string, allowMissingDB bool) (string, string, error) {
	rootAbs, err := filepath.Abs(fixtureRoot)
	if err != nil {
		return "", "", err
	}
	info, err := os.Lstat(rootAbs)
	if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm() != 0o700 {
		return "", "", errors.New("fixture root must be an existing real directory with mode 0700")
	}
	markerPath := filepath.Join(rootAbs, ".cicada-v68-owned")
	markerInfo, err := os.Lstat(markerPath)
	if err != nil || !markerInfo.Mode().IsRegular() || markerInfo.Mode().Perm() != 0o600 ||
		markerInfo.Mode()&os.ModeSymlink != 0 {
		return "", "", errors.New("fixture root lacks a private V68 ownership marker")
	}
	owner, ok := markerInfo.Sys().(*syscall.Stat_t)
	if !ok || owner.Uid != uint32(os.Geteuid()) {
		return "", "", errors.New("V68 ownership marker does not belong to this fixture operator")
	}
	marker, err := os.ReadFile(markerPath)
	if err != nil || !strings.HasPrefix(string(marker), "cicada.v68.disposable.v1\n") ||
		len(marker) > 128 || !strings.HasSuffix(string(marker), "\n") {
		return "", "", errors.New("V68 ownership marker has an invalid fixture identity")
	}
	dbAbs, err := filepath.Abs(dbPath)
	if err != nil {
		return "", "", errors.New("fixture database path is invalid")
	}
	relativeDB, err := filepath.Rel(rootAbs, dbAbs)
	if err != nil || relativeDB == "." || relativeDB == ".." || strings.HasPrefix(relativeDB, ".."+string(filepath.Separator)) {
		return "", "", errors.New("V68 fixture database must remain beneath its owned fixture directory")
	}
	dbInfo, dbErr := os.Lstat(dbAbs)
	if allowMissingDB {
		if !errors.Is(dbErr, os.ErrNotExist) {
			return "", "", errors.New("bootstrap refuses an existing or unsafe fixture database")
		}
	} else {
		if dbErr != nil || !dbInfo.Mode().IsRegular() || dbInfo.Mode()&os.ModeSymlink != 0 {
			return "", "", errors.New("fixture database is missing or is not a regular owned file")
		}
		if dbOwner, ok := dbInfo.Sys().(*syscall.Stat_t); !ok || dbOwner.Uid != uint32(os.Geteuid()) {
			return "", "", errors.New("fixture database does not belong to this fixture operator")
		}
	}
	return dbAbs, rootAbs, nil
}

func bootstrap(raw []string) error {
	flags := flag.NewFlagSet("cicada-v68fixture bootstrap", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	db := flags.String("db", "", "fixture Hub SQLite database")
	directory := flags.String("fixture", "", "owned mode-0700 fixture root")
	threadA := flags.String("native-thread-a", "", "real thread.started UUID; positioning input only, not Join evidence")
	threadB := flags.String("native-thread-b", "", "real thread.started UUID; positioning input only, not Join evidence")
	if err := flags.Parse(raw); err != nil || len(flags.Args()) != 0 || *db == "" || *directory == "" {
		return errors.New("bootstrap requires --db and --fixture")
	}
	if err := validateNativeThreads(*threadA, *threadB); err != nil {
		return err
	}
	dbPath, root, err := validateOwnedFixturePaths(*db, *directory, true)
	if err != nil {
		return err
	}
	if _, err := os.Lstat(filepath.Join(root, "fixture.json")); err == nil {
		return errors.New("fixture metadata already exists; refusing to overwrite")
	}
	stateDir := filepath.Dir(dbPath)
	if err := os.MkdirAll(filepath.Join(stateDir, "e2ee"), 0o700); err != nil {
		return err
	}
	hubIdentity, err := e2ee.NewIdentity()
	if err != nil {
		return err
	}
	hubPrivate, err := hubIdentity.MarshalBinary()
	if err != nil {
		return err
	}
	if err := writeExclusive(filepath.Join(stateDir, "e2ee", "identity.json"), hubPrivate, 0o600); err != nil {
		return err
	}
	owner, err := e2ee.NewIdentity()
	if err != nil {
		return err
	}
	ownerPrivate, err := owner.MarshalBinary()
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Join(root, "owner-private"), 0o700); err != nil {
		return err
	}
	if err := writeExclusive(filepath.Join(root, "owner-private", "owner.key"), ownerPrivate, 0o600); err != nil {
		return err
	}
	if err := writeJSONExclusive(filepath.Join(root, "owner-public.json"), owner.Public(), 0o600); err != nil {
		return err
	}

	persistence, err := store.New(dbPath)
	if err != nil {
		return err
	}
	defer persistence.Close()
	hubID, err := persistence.GetClientHubID()
	if err != nil {
		return err
	}
	ownerID := hubIdentity.Public().ID
	ownerPrincipal, err := persistence.CreatePrincipal(store.Principal{ID: ownerID,
		Kind: store.PrincipalKindHuman, OwnerID: ownerID, TrustDomainID: ownerID,
		Name: "synthetic V68 Owner", Status: store.PrincipalStatusActive})
	if err != nil {
		return err
	}
	var suffixBytes [8]byte
	if _, err := rand.Read(suffixBytes[:]); err != nil {
		return errors.New("could not allocate synthetic V68 fixture identifiers")
	}
	fixtureSuffix := hex.EncodeToString(suffixBytes[:])
	groupID := "group_v68_" + fixtureSuffix
	group, err := persistence.CreateGroup(store.Group{ID: groupID, Name: "synthetic V68 sealed group",
		OwnerPrincipalID: ownerPrincipal.ID, TrustDomainID: ownerID, State: store.GroupStateActive})
	if err != nil {
		return err
	}
	ownerKey, err := persistence.RegisterOwnerApprovalKeyLocal(ownerID, owner.Public())
	if err != nil {
		return err
	}
	client, err := e2ee.NewIdentity()
	if err != nil {
		return err
	}
	deviceID := "client_v68_" + fixtureSuffix
	now := time.Now().UTC()
	deviceGrant, err := owner.SignOwnerDeviceGrant(ownerID, deviceID, client.Public(), hubID,
		e2ee.OwnerDevicePurposeControl, now.Add(-time.Minute), now.Add(time.Hour))
	if err != nil {
		return err
	}
	if _, err := persistence.RegisterClientDeviceFromOwnerGrant(store.RegisterClientDeviceInput{
		OwnerID: ownerID, OwnerKeyID: ownerKey.KeyID, DeviceID: deviceID,
		DevicePublic: client.Public(), OwnerDeviceGrant: deviceGrant,
	}); err != nil {
		return err
	}

	meta := fixture{Version: 1, HubID: hubID, OwnerID: ownerID, OwnerKeyID: ownerKey.KeyID,
		GroupID: group.ID, NodeA: "node_v68_a_" + fixtureSuffix,
		NodeB:   "node_v68_b_" + fixtureSuffix,
		ThreadA: "thread_v68_a_" + fixtureSuffix,
		ThreadB: "thread_v68_b_" + fixtureSuffix, DeviceID: deviceID,
		SourceState: filepath.Join(root, "node-a-state"), TargetState: filepath.Join(root, "node-b-state")}
	if *threadA != "" {
		meta.ThreadA, meta.ThreadB = *threadA, *threadB
	}
	for _, node := range []struct{ id, state string }{{meta.NodeA, meta.SourceState}, {meta.NodeB, meta.TargetState}} {
		token, digest, err := fabric.NewNodeCredential()
		if err != nil {
			return err
		}
		code := sha256.Sum256([]byte("synthetic-v68-bind\x00" + node.id))
		codeDigest := hex.EncodeToString(code[:])
		if _, err := persistence.CreatePendingNodeDeviceBinding(node.id, node.id, digest,
			codeDigest, time.Now().UTC().Add(10*time.Minute)); err != nil {
			return err
		}
		if _, err := persistence.ConfirmPendingNodeDeviceBinding(ownerID, deviceID, codeDigest); err != nil {
			return err
		}
		if err := provisionNodeState(node.state, node.id, token, ownerID, ownerKey.KeyID, owner.Public()); err != nil {
			return err
		}
	}
	return writeJSONExclusive(filepath.Join(root, "fixture.json"), meta, 0o600)
}

// These coordinates never create a SessionBinding or a native session record.
// The native driver must independently observe thread.started and perform Join.
func validateNativeThreads(a, b string) error {
	if a == "" && b == "" {
		return nil // Preserve the recording-queue V68 fixture's existing default.
	}
	canonical := regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$`)
	if !canonical.MatchString(a) || !canonical.MatchString(b) || a == b ||
		a == "00000000-0000-0000-0000-000000000000" || b == "00000000-0000-0000-0000-000000000000" {
		return errors.New("native fixture inputs require two distinct nonzero canonical lowercase UUIDs")
	}
	return nil
}

func provisionNodeState(stateDir, nodeID, token, ownerID, ownerKeyID string,
	ownerPublic e2ee.PublicIdentity) error {
	if err := os.MkdirAll(stateDir, 0o700); err != nil {
		return err
	}
	identityDir := filepath.Join(stateDir, "nodes", "node-"+nodeID)
	if err := os.MkdirAll(identityDir, 0o700); err != nil {
		return err
	}
	if err := writeJSONExclusive(filepath.Join(identityDir, "identity.json"), map[string]any{
		"version": 1, "node_id": nodeID,
	}, 0o600); err != nil {
		return err
	}
	if err := writeExclusive(filepath.Join(identityDir, "relay.token"), []byte(token+"\n"), 0o600); err != nil {
		return err
	}
	crypto, err := nodekeys.OpenCryptoState(identityDir)
	if err != nil {
		return err
	}
	fingerprint, err := nodekeys.PeerKeyFingerprint(ownerPublic)
	if err == nil {
		_, err = crypto.TrustOwnerApprovalKeyLocal(ownerID, ownerKeyID, ownerPublic, fingerprint)
	}
	closeErr := crypto.Close()
	if err != nil {
		return err
	}
	return closeErr
}

func approve(raw []string) error {
	dbPath, root, err := args("approve", raw)
	if err != nil {
		return err
	}
	meta, err := readFixture(root)
	if err != nil {
		return err
	}
	owner, err := loadOwner(root)
	if err != nil {
		return err
	}
	persistence, err := store.New(dbPath)
	if err != nil {
		return err
	}
	defer persistence.Close()
	for _, threadID := range []string{meta.ThreadA, meta.ThreadB} {
		endpoint, err := persistence.GetEndpointV2BySession("codex", threadID)
		if err != nil || endpoint == nil || endpoint.MachineID == "" {
			return errors.New("synthetic Node Group Join Endpoint is missing")
		}
		manifest, err := persistence.PreviewGroupEndpointKeyGrant(meta.OwnerID, meta.GroupID,
			endpoint.ID, meta.OwnerKeyID, time.Now().UTC().Add(-time.Minute), time.Now().UTC().Add(time.Hour))
		if err != nil {
			return err
		}
		issued, err := time.Parse(time.RFC3339Nano, manifest.IssuedAt)
		if err != nil {
			return err
		}
		expires, err := time.Parse(time.RFC3339Nano, manifest.ExpiresAt)
		if err != nil {
			return err
		}
		proof, err := owner.SignOwnerLinkKeyGrant(meta.OwnerID, store.GroupEndpointKeyGrantOperation,
			manifest.Digest, manifest.CandidateBindingDigest, uint64(manifest.CandidateVersion),
			e2ee.OwnerLinkGrantSideSource, issued, expires)
		if err != nil {
			return err
		}
		if _, err := persistence.AcceptGroupEndpointKeyGrant(meta.OwnerID, meta.GroupID,
			endpoint.ID, meta.OwnerKeyID, proof); err != nil {
			return err
		}
	}
	fmt.Println(`{"status":"OWNER_GRANTS_APPROVED_FOR_TWO_SYNTHETIC_ENDPOINTS"}`)
	return nil
}

func v68ExpectedPayloadMatches(profile string, payload []byte, reply bool) bool {
	switch profile {
	case "legacy-v68":
		marker := "CICADA-V68-PLAINTEXT-NEVER-IN-RELAY"
		if reply {
			marker = "CICADA-V68-REPLY-ONLY-OPAQUE"
		}
		return len(payload) > 0 && bytes.Contains(payload, []byte(marker))
	case "managed-native":
		pattern := `^CICADA-MANAGED-PLAINTEXT-NEVER-IN-RELAY:[0-9a-f]{16}$`
		if reply {
			pattern = `^CICADA-MANAGED-REPLY-ONLY-OPAQUE:CICADA-ORIGINAL-B-[0-9a-f]{32}$`
		}
		return regexp.MustCompile(pattern).Match(payload)
	default:
		return false
	}
}

func check(raw []string) error {
	flags := flag.NewFlagSet("cicada-v68fixture check", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	dbPath := flags.String("db", "", "fixture Hub SQLite database")
	root := flags.String("fixture", "", "owned mode-0700 fixture root")
	messageID := flags.String("message-id", "", "sealed relay message ID")
	plaintext := flags.String("plaintext-file", "", "private file with expected payload; never printed")
	replyPlaintext := flags.String("reply-plaintext-file", "", "private file with expected reply; never printed")
	requestID := flags.String("request-id", "", "ASK lifecycle request ID")
	payloadProfile := flags.String("payload-profile", "legacy-v68", "expected payload profile: legacy-v68 or managed-native")
	if err := flags.Parse(raw); err != nil || len(flags.Args()) != 0 || *dbPath == "" || *root == "" ||
		*messageID == "" || *plaintext == "" || *replyPlaintext == "" || *requestID == "" {
		return errors.New("check requires --db, --fixture, --message-id, --request-id, --plaintext-file, and --reply-plaintext-file")
	}
	if *payloadProfile != "legacy-v68" && *payloadProfile != "managed-native" {
		return errors.New("unknown expected payload profile")
	}
	payloadMarker := "CICADA-V68-PLAINTEXT-NEVER-IN-RELAY"
	if *payloadProfile == "managed-native" {
		payloadMarker = "CICADA-MANAGED-PLAINTEXT-NEVER-IN-RELAY"
	}
	validatedDB, rootAbs, err := validateOwnedFixturePaths(*dbPath, *root, false)
	if err != nil {
		return err
	}
	meta, err := readFixture(rootAbs)
	if err != nil {
		return err
	}
	payloadInfo, err := os.Lstat(*plaintext)
	if err != nil || !payloadInfo.Mode().IsRegular() || payloadInfo.Mode().Perm() != 0o600 {
		return errors.New("expected payload must be a regular mode-0600 private fixture file")
	}
	expectedPayload, err := os.ReadFile(*plaintext)
	if err != nil || !v68ExpectedPayloadMatches(*payloadProfile, expectedPayload, false) {
		return errors.New("expected payload file is missing or empty")
	}
	replyInfo, err := os.Lstat(*replyPlaintext)
	if err != nil || !replyInfo.Mode().IsRegular() || replyInfo.Mode().Perm() != 0o600 {
		return errors.New("expected reply must be a regular mode-0600 private fixture file")
	}
	expectedReply, err := os.ReadFile(*replyPlaintext)
	if err != nil || !v68ExpectedPayloadMatches(*payloadProfile, expectedReply, true) {
		return errors.New("expected reply file is missing or empty")
	}
	persistence, err := store.New(validatedDB)
	if err != nil {
		return err
	}
	defer persistence.Close()
	record, err := persistence.GetRelaySealedV1(*messageID)
	if err != nil || record == nil || record.PayloadMode != store.RelayPayloadModeSealedV1 ||
		record.Route.MessageID != *messageID || record.Route.Kind != "ask" ||
		record.Route.SenderEndpointID == "" || record.Route.ReceiverEndpointID == "" ||
		record.Security.SenderGroupID != meta.GroupID || record.Security.ReceiverGroupID != meta.GroupID ||
		bytes.Contains(record.Ciphertext, []byte(payloadMarker)) {
		return errors.New("sealed relay record is absent or its opaque bytes do not match the fixture sentinel expectations")
	}
	if bytes.Contains(record.Ciphertext, expectedPayload) {
		return errors.New("Hub relay ciphertext contains the known plaintext fixture marker")
	}
	if _, err := persistence.GetRelayMessage(*messageID); !errors.Is(err, store.ErrRelayPayloadModeMismatch) {
		return errors.New("sealed ASK became readable through the plaintext relay API")
	}
	tokenPath := filepath.Join(meta.SourceState, "nodes", "node-"+meta.NodeA, "relay.token")
	tokenInfo, err := os.Lstat(tokenPath)
	if err != nil || !tokenInfo.Mode().IsRegular() || tokenInfo.Mode().Perm() != 0o600 {
		return errors.New("source Node credential fixture is missing or unsafe")
	}
	token, err := os.ReadFile(tokenPath)
	if err != nil {
		return err
	}
	request, err := persistence.GetSameGroupSealedV1RequestStatus(fabric.HashSessionCredential(strings.TrimSpace(string(token))), *requestID)
	if err != nil || request == nil || request.MessageID != *messageID || request.SenderGroupID != meta.GroupID ||
		request.SenderEndpointID != record.Route.SenderEndpointID ||
		request.ReceiverEndpointID != record.Route.ReceiverEndpointID || request.State != store.FabricRequestReplied ||
		request.ReplyMessageID == "" {
		return errors.New("durable ASK/REPLY request status did not reach REPLIED for the exact sealed ASK")
	}
	reply, err := persistence.GetRelaySealedV1(request.ReplyMessageID)
	if err != nil || reply == nil || reply.PayloadMode != store.RelayPayloadModeSealedV1 ||
		!v68ReplyCorrelationMatches(reply.Route, *requestID, request.MessageID) ||
		reply.Route.SenderEndpointID != record.Route.ReceiverEndpointID ||
		reply.Route.ReceiverEndpointID != record.Route.SenderEndpointID ||
		reply.Security.SenderGroupID != meta.GroupID || reply.Security.ReceiverGroupID != meta.GroupID ||
		bytes.Contains(reply.Ciphertext, expectedPayload) || bytes.Contains(reply.Ciphertext, expectedReply) {
		return errors.New("durable reply route is missing, mis-correlated, or contains known plaintext")
	}
	if _, err := persistence.GetRelayMessage(request.ReplyMessageID); !errors.Is(err, store.ErrRelayPayloadModeMismatch) {
		return errors.New("sealed REPLY became readable through the plaintext relay API")
	}
	receipts, err := persistence.ListRelayReceipts(*messageID, 100)
	if err != nil {
		return err
	}
	queueAccepted := false
	for _, receipt := range receipts {
		if receipt.Layer == store.RelayReceiptCodexQueueAccepted {
			queueAccepted = true
		}
		if receipt.Layer == store.RelayReceiptApplicationAck {
			return errors.New("Node bearer incorrectly recorded an application-level ACK")
		}
	}
	if !queueAccepted {
		return errors.New("durable relay history lacks the expected recording-queue acceptance receipt")
	}
	fmt.Println(`{"status":"SEALED_ASK_REPLY_REPLIED","control":"fabric-only"}`)
	return nil
}

func readFixture(root string) (fixture, error) {
	info, err := os.Lstat(filepath.Join(root, "fixture.json"))
	if err != nil || !info.Mode().IsRegular() || info.Mode().Perm() != 0o600 {
		return fixture{}, errors.New("V68 fixture metadata is missing or unsafe")
	}
	data, err := os.ReadFile(filepath.Join(root, "fixture.json"))
	if err != nil {
		return fixture{}, err
	}
	var meta fixture
	if err := json.Unmarshal(data, &meta); err != nil || meta.Version != 1 || meta.HubID == "" ||
		meta.OwnerID == "" || meta.OwnerKeyID == "" || meta.GroupID == "" || meta.NodeA == "" || meta.NodeB == "" ||
		meta.ThreadA == "" || meta.ThreadB == "" || meta.SourceState == "" || meta.TargetState == "" {
		return fixture{}, errors.New("V68 fixture metadata has invalid public identity coordinates")
	}
	return meta, nil
}

func loadOwner(root string) (*e2ee.Identity, error) {
	path := filepath.Join(root, "owner-private", "owner.key")
	info, err := os.Lstat(path)
	if err != nil || !info.Mode().IsRegular() || info.Mode().Perm() != 0o600 {
		return nil, errors.New("synthetic Owner key must be a regular mode-0600 fixture file")
	}
	wire, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	return e2ee.UnmarshalIdentity(wire)
}

func writeExclusive(path string, data []byte, mode os.FileMode) error {
	file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, mode)
	if err != nil {
		return err
	}
	if _, err := file.Write(data); err != nil {
		_ = file.Close()
		_ = os.Remove(path)
		return err
	}
	if err := file.Sync(); err != nil {
		_ = file.Close()
		_ = os.Remove(path)
		return err
	}
	return file.Close()
}

func writeJSONExclusive(path string, value any, mode os.FileMode) error {
	data, err := json.MarshalIndent(value, "", "  ")
	if err != nil {
		return err
	}
	return writeExclusive(path, append(data, '\n'), mode)
}
