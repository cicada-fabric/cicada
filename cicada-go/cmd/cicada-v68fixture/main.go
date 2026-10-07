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
	"github.com/cicada-ai/cicada/internal/clientwire"
	"io"
	"net"
	"net/http"
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
	Scenario           string `json:"scenario,omitempty"`
	AliceSecondGroupID string `json:"alice_second_group_id,omitempty"`
	BobOwnerID         string `json:"bob_owner_id,omitempty"`
	BobOwnerKeyID      string `json:"bob_owner_key_id,omitempty"`
	BobGroupID         string `json:"bob_group_id,omitempty"`
	BobDeviceID        string `json:"bob_device_id,omitempty"`
	Version            int    `json:"version"`
	HubID              string `json:"hub_id"`
	OwnerID            string `json:"owner_id"`
	OwnerKeyID         string `json:"owner_key_id"`
	GroupID            string `json:"group_id"`
	NodeA              string `json:"node_a"`
	NodeB              string `json:"node_b"`
	ThreadA            string `json:"thread_a"`
	ThreadB            string `json:"thread_b"`
	DeviceID           string `json:"device_id"`
	SourceState        string `json:"source_state"`
	TargetState        string `json:"target_state"`
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
	case "tls-bootstrap":
		err = dispatchTLSBootstrap(os.Args[2:])
	case "approve":
		err = approve(os.Args[2:])
	case "check":
		err = check(os.Args[2:])
	case "g2-authorize-second":
		err = authorizeG2Second(os.Args[2:])
	case "g2-revoke":
		err = revokeG2(os.Args[2:])
	case "control-snapshot":
		err = controlSnapshot(os.Args[2:])
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
	scenario := flags.String("scenario", "g1", "explicit g1 or g2-g3 synthetic fixture authority")
	db := flags.String("db", "", "fixture Hub SQLite database")
	directory := flags.String("fixture", "", "owned mode-0700 fixture root")
	threadA := flags.String("native-thread-a", "", "real thread.started UUID; positioning input only, not Join evidence")
	threadB := flags.String("native-thread-b", "", "real thread.started UUID; positioning input only, not Join evidence")
	if err := flags.Parse(raw); err != nil || len(flags.Args()) != 0 || *db == "" || *directory == "" {
		return errors.New("bootstrap requires --db and --fixture")
	}
	if err := validateFixtureScenario(*scenario); err != nil {
		return err
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
	if *scenario == "g2-g3" {
		ownerID = owner.Public().ID
	}
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
	contextPolicy := ""
	if *scenario == "g2-g3" {
		contextPolicy = "group_scoped"
	}
	group, err := persistence.CreateGroup(store.Group{ID: groupID, Name: "synthetic V68 sealed group",
		OwnerPrincipalID: ownerPrincipal.ID, TrustDomainID: ownerID, ContextPolicy: contextPolicy, State: store.GroupStateActive})
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
	bobOwner, bobOwnerID, bobOwnerKeyID, bobDeviceID := owner, ownerID, ownerKey.KeyID, deviceID
	if *scenario == "g2-g3" {
		meta.Scenario = *scenario
		clientWire, err := client.MarshalBinary()
		if err != nil {
			return err
		}
		if err := writeExclusive(filepath.Join(root, "owner-private", "device.key"), clientWire, 0o600); err != nil {
			return err
		}
		meta.AliceSecondGroupID = "group_v68_alice_second_" + fixtureSuffix
		if _, err := persistence.CreateGroup(store.Group{ID: meta.AliceSecondGroupID,
			Name: "synthetic Alice independent second Group", OwnerPrincipalID: ownerID,
			TrustDomainID: ownerID, ContextPolicy: "group_scoped", State: store.GroupStateActive}); err != nil {
			return err
		}
		bobOwner, err = e2ee.NewIdentity()
		if err != nil {
			return err
		}
		bobOwnerID = "owner_v68_bob_" + fixtureSuffix
		if _, err := persistence.CreatePrincipal(store.Principal{ID: bobOwnerID,
			Kind: store.PrincipalKindHuman, OwnerID: bobOwnerID, TrustDomainID: bobOwnerID,
			Name: "synthetic independent Bob Owner", Status: store.PrincipalStatusActive}); err != nil {
			return err
		}
		bobKey, err := persistence.RegisterOwnerApprovalKeyLocal(bobOwnerID, bobOwner.Public())
		if err != nil {
			return err
		}
		bobOwnerKeyID = bobKey.KeyID
		bobDeviceID = "client_v68_bob_" + fixtureSuffix
		bobClient, err := e2ee.NewIdentity()
		if err != nil {
			return err
		}
		bobGrant, err := bobOwner.SignOwnerDeviceGrant(bobOwnerID, bobDeviceID, bobClient.Public(), hubID,
			e2ee.OwnerDevicePurposeControl, now.Add(-time.Minute), now.Add(time.Hour))
		if err != nil {
			return err
		}
		if _, err := persistence.RegisterClientDeviceFromOwnerGrant(store.RegisterClientDeviceInput{
			OwnerID: bobOwnerID, OwnerKeyID: bobOwnerKeyID, DeviceID: bobDeviceID,
			DevicePublic: bobClient.Public(), OwnerDeviceGrant: bobGrant}); err != nil {
			return err
		}
		meta.BobGroupID = "group_v68_bob_" + fixtureSuffix
		if _, err := persistence.CreateGroup(store.Group{ID: meta.BobGroupID,
			Name: "synthetic Bob private Group", OwnerPrincipalID: bobOwnerID,
			TrustDomainID: bobOwnerID, ContextPolicy: "group_scoped", State: store.GroupStateActive}); err != nil {
			return err
		}
		meta.BobOwnerID, meta.BobOwnerKeyID, meta.BobDeviceID = bobOwnerID, bobOwnerKeyID, bobDeviceID
		if err := os.MkdirAll(filepath.Join(root, "bob-owner-private"), 0o700); err != nil {
			return err
		}
		for name, identity := range map[string]*e2ee.Identity{"owner.key": bobOwner, "device.key": bobClient} {
			wire, err := identity.MarshalBinary()
			if err != nil {
				return err
			}
			if err := writeExclusive(filepath.Join(root, "bob-owner-private", name), wire, 0o600); err != nil {
				return err
			}
		}
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
		nodeOwnerID, nodeKeyID, nodeDeviceID, nodeOwner := ownerID, ownerKey.KeyID, deviceID, owner
		if node.id == meta.NodeB {
			nodeOwnerID, nodeKeyID, nodeDeviceID, nodeOwner = bobOwnerID, bobOwnerKeyID, bobDeviceID, bobOwner
		}
		if _, err := persistence.ConfirmPendingNodeDeviceBinding(nodeOwnerID, nodeDeviceID, codeDigest); err != nil {
			return err
		}
		if err := provisionNodeState(node.state, node.id, token, nodeOwnerID, nodeKeyID, nodeOwner.Public()); err != nil {
			return err
		}
		if *scenario == "g2-g3" {
			crypto, err := nodekeys.OpenCryptoState(filepath.Join(node.state, "nodes", "node-"+node.id))
			if err != nil {
				return err
			}
			for _, trusted := range []struct {
				id, key string
				public  e2ee.PublicIdentity
			}{{ownerID, ownerKey.KeyID, owner.Public()}, {bobOwnerID, bobOwnerKeyID, bobOwner.Public()}} {
				fingerprint, err := nodekeys.PeerKeyFingerprint(trusted.public)
				if err != nil {
					crypto.Close()
					return err
				}
				if _, err := crypto.TrustOwnerApprovalKeyLocal(trusted.id, trusted.key, trusted.public, fingerprint); err != nil {
					crypto.Close()
					return err
				}
			}
			if err := crypto.Close(); err != nil {
				return err
			}
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
	if meta.Scenario == "g2-g3" {
		return approveG2(dbPath, root, meta)
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

// Scenario selection is explicit and checked before any fixture access.
func validateFixtureScenario(scenario string) error {
	if scenario != "g1" && scenario != "g2-g3" {
		return errors.New("unsupported fixture scenario")
	}
	return nil
}

// G2 consent is derived only from actual joined Endpoint bindings and current
// Endpoint key candidates. This helper never creates a native SessionBinding.
func approveG2(dbPath, root string, meta fixture) error {
	if meta.Scenario != "g2-g3" || meta.BobOwnerID == "" || meta.BobOwnerID == meta.OwnerID ||
		meta.AliceSecondGroupID == "" || meta.BobGroupID == "" {
		return errors.New("G2 authority coordinates are incomplete")
	}
	s, err := store.New(dbPath)
	if err != nil {
		return err
	}
	defer s.Close()
	a, err := s.GetEndpointV2BySession("codex", meta.ThreadA)
	if err != nil || a == nil || a.MachineID != meta.NodeA {
		return errors.New("G2 original A Endpoint missing")
	}
	b, err := s.GetEndpointV2BySession("codex", meta.ThreadB)
	if err != nil || b == nil || b.MachineID != meta.NodeB || a.ID == b.ID {
		return errors.New("G2 original B Endpoint missing")
	}
	owners := []struct {
		id, keyID, groupID, endpointID, path, side string
		role                                       e2ee.OwnerLinkGrantSide
	}{
		{meta.OwnerID, meta.OwnerKeyID, meta.AliceSecondGroupID, a.ID, "owner-private", store.CommunicationLinkGrantSource, e2ee.OwnerLinkGrantSideSource},
		{meta.BobOwnerID, meta.BobOwnerKeyID, meta.BobGroupID, b.ID, "bob-owner-private", store.CommunicationLinkGrantTarget, e2ee.OwnerLinkGrantSideTarget},
	}
	identities := make([]*e2ee.Identity, len(owners))
	for i, owner := range owners {
		identities[i], err = loadFixtureIdentity(root, owner.path, "owner.key")
		if err != nil {
			return err
		}
		manifest, err := s.PreviewGroupEndpointKeyGrant(owner.id, owner.groupID, owner.endpointID, owner.keyID,
			time.Now().UTC().Add(-time.Minute), time.Now().UTC().Add(time.Hour))
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
		proof, err := identities[i].SignOwnerLinkKeyGrant(owner.id, store.GroupEndpointKeyGrantOperation,
			manifest.Digest, manifest.CandidateBindingDigest, uint64(manifest.CandidateVersion), e2ee.OwnerLinkGrantSideSource, issued, expires)
		if err != nil {
			return err
		}
		if _, err := s.AcceptGroupEndpointKeyGrant(owner.id, owner.groupID, owner.endpointID, owner.keyID, proof); err != nil {
			return err
		}
	}
	invite, err := s.CreateExternalThreadInvite(store.ExternalThreadInviteInput{
		OwnerID: meta.OwnerID, SourceEndpointID: a.ID, SourceGroupID: meta.AliceSecondGroupID,
		HubID: meta.HubID, Direction: "forward", Actions: []string{"ask", "reply"},
		DataScopes: []string{"thread.message"}, ExpiresAt: time.Now().UTC().Add(time.Hour).Truncate(time.Second).Format(time.RFC3339),
	})
	if err != nil {
		return err
	}
	accepted, err := s.AcceptExternalThreadInvite(invite.Token, meta.BobOwnerID, b.ID, meta.BobGroupID)
	if err != nil {
		return err
	}
	link, err := s.GetCommunicationLinkForOwner(accepted.LinkID, meta.OwnerID)
	if err != nil || link == nil {
		return errors.New("G2 accepted exact Link missing")
	}
	linkExpiry, err := time.Parse(time.RFC3339, link.ExpiresAt)
	if err != nil {
		return err
	}
	for i, owner := range owners {
		manifest, err := s.GetCommunicationLinkKeyManifest(link.ID, owner.id)
		if err != nil {
			return err
		}
		proof, err := identities[i].SignOwnerLinkKeyGrant(owner.id, link.ID, link.ContractDigest, manifest.Digest,
			uint64(link.Version), owner.role, time.Now().UTC().Add(-time.Minute), linkExpiry)
		if err != nil {
			return err
		}
		if _, err := s.RecordCommunicationLinkKeyGrant(owner.id, link.ID, owner.side, owner.keyID, proof); err != nil {
			return err
		}
	}
	for _, owner := range owners {
		statuses, err := s.GetCommunicationLinkKeyGrantStatuses(link.ID, owner.id)
		if err != nil || len(statuses) != 2 {
			return errors.New("G2 current key grant evidence missing")
		}
		for _, status := range statuses {
			if status.CurrentStatus != store.CommunicationLinkKeyGrantAccepted {
				return errors.New("G2 key grant no longer current")
			}
		}

	}
	if err := writeJSONExclusive(filepath.Join(root, "g2-link.json"), map[string]string{"link_id": link.ID, "source_endpoint_id": a.ID, "target_endpoint_id": b.ID}, 0o600); err != nil {
		return err
	}
	fmt.Println(`{"status":"G2_CURRENT_ENDPOINTS_BILATERAL_KEY_CONSENT_RECORDED"}`)
	return nil
}

func loadFixtureIdentity(root, directory, name string) (*e2ee.Identity, error) {
	if (directory != "owner-private" && directory != "bob-owner-private") || (name != "owner.key" && name != "device.key") {
		return nil, errors.New("unknown fixture identity role")
	}
	rootInfo, err := os.Lstat(root)
	if err != nil || !rootInfo.IsDir() || rootInfo.Mode().Perm() != 0o700 || rootInfo.Mode()&os.ModeSymlink != 0 {
		return nil, errors.New("unsafe fixture identity root")
	}
	parentInfo, err := os.Lstat(filepath.Join(root, directory))
	if err != nil || !parentInfo.IsDir() || parentInfo.Mode().Perm() != 0o700 || parentInfo.Mode()&os.ModeSymlink != 0 {
		return nil, errors.New("unsafe fixture identity parent")
	}
	for _, info := range []os.FileInfo{rootInfo, parentInfo} {
		owner, ok := info.Sys().(*syscall.Stat_t)
		if !ok || owner.Uid != uint32(os.Geteuid()) {
			return nil, errors.New("fixture identity owner mismatch")
		}
	}
	path := filepath.Join(root, directory, name)
	info, err := os.Lstat(path)
	if err != nil || !info.Mode().IsRegular() || info.Mode().Perm() != 0o600 {
		return nil, errors.New("fixture identity must be regular mode0600")
	}
	owner, ok := info.Sys().(*syscall.Stat_t)
	if !ok || owner.Uid != uint32(os.Geteuid()) {
		return nil, errors.New("fixture identity file owner mismatch")
	}
	wire, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	return e2ee.UnmarshalIdentity(wire)
}

// Return only the authority already selected by this owned fixture. Unknown
// Nodes never inherit Alice authority. G1 coordinates remain unchanged.
func fixtureNodeScope(meta fixture, nodeID string) (string, string, string, string, error) {
	if nodeID != meta.NodeA && nodeID != meta.NodeB {
		return "", "", "", "", errors.New("unknown fixture Node")
	}
	if meta.Scenario != "" && meta.Scenario != "g2-g3" {
		return "", "", "", "", errors.New("unknown fixture scenario")
	}
	if meta.Scenario == "g2-g3" && nodeID == meta.NodeB {
		if meta.BobOwnerID == "" || meta.BobOwnerID == meta.OwnerID || meta.BobOwnerKeyID == "" || meta.BobDeviceID == "" || meta.BobGroupID == "" {
			return "", "", "", "", errors.New("incomplete Bob authority")
		}
		return meta.BobOwnerID, meta.BobOwnerKeyID, meta.BobDeviceID, meta.BobGroupID, nil
	}
	return meta.OwnerID, meta.OwnerKeyID, meta.DeviceID, meta.GroupID, nil
}

// This local synthetic authority grants membership only after a real first Join.
func validateG2SecondAuthority(meta fixture, endpoint *store.Endpoint, principal *store.Principal, binding *store.SessionBinding, group *store.Group) error {
	if meta.Scenario != "g2-g3" || meta.AliceSecondGroupID == "" || meta.AliceSecondGroupID == meta.GroupID || endpoint == nil || principal == nil || binding == nil || group == nil {
		return errors.New("G2 second authority incomplete")
	}
	if endpoint.ID == "" || endpoint.PrincipalID != principal.ID || endpoint.Owner != meta.OwnerID || endpoint.MachineID != meta.NodeA || endpoint.Harness != "codex" || endpoint.NativeSessionID != meta.ThreadA || endpoint.Status != "online" {
		return errors.New("G2 original A Endpoint mismatch")
	}
	if principal.Kind != store.PrincipalKindAgent || principal.Status != store.PrincipalStatusActive || principal.OwnerID != meta.OwnerID || principal.TrustDomainID != meta.OwnerID {
		return errors.New("G2 original A Principal mismatch")
	}
	if binding.ID == "" || binding.ID != endpoint.BindingID || (binding.Status != store.SessionBindingStatusActive && binding.Status != store.SessionBindingStatusLeased) || binding.EndpointID != endpoint.ID || binding.PrincipalID != principal.ID || binding.NodeID != meta.NodeA || binding.NativeSessionID != meta.ThreadA || binding.GroupID != meta.GroupID || binding.Epoch == 0 {
		return errors.New("G2 original A binding mismatch")
	}
	expires, err := time.Parse(time.RFC3339Nano, binding.LeaseExpiresAt)
	if err != nil || !expires.After(time.Now().UTC()) {
		return errors.New("G2 original A lease expired")
	}
	if group.ID != meta.AliceSecondGroupID || group.State != store.GroupStateActive || group.OwnerPrincipalID != meta.OwnerID || group.TrustDomainID != meta.OwnerID || group.NetworkID != "" || group.ContextPolicy != "group_scoped" {
		return errors.New("G2 exact second Group mismatch")
	}
	return nil
}
func authorizeG2Second(raw []string) error {
	db, root, err := args("g2-authorize-second", raw)
	if err != nil {
		return err
	}
	meta, err := readFixture(root)
	if err != nil || meta.Scenario != "g2-g3" {
		return errors.New("G2 owned scenario required")
	}
	s, err := store.New(db)
	if err != nil {
		return err
	}
	defer s.Close()
	endpoint, err := s.GetEndpointV2BySession("codex", meta.ThreadA)
	if err != nil || endpoint == nil {
		return errors.New("G2 real original A Join required")
	}
	principal, err := s.GetPrincipal(endpoint.PrincipalID)
	if err != nil {
		return err
	}
	binding, err := s.GetActiveSessionBinding(endpoint.ID)
	if err != nil {
		return err
	}
	group, err := s.GetGroup(meta.AliceSecondGroupID)
	if err != nil {
		return err
	}
	if err := validateG2SecondAuthority(meta, endpoint, principal, binding, group); err != nil {
		return err
	}
	if err := s.ValidateSessionBindingLease(binding.ID, binding.LeaseOwner, binding.Epoch); err != nil {
		return errors.New("G2 original A lease not current")
	}
	if _, err := s.GetMembershipByPrincipalGroup(principal.ID, group.ID); !errors.Is(err, store.ErrMembershipNotFound) {
		return errors.New("G2 second membership must be absent before explicit authorization")
	}
	_, err = s.CreateMembership(store.Membership{PrincipalID: principal.ID, GroupID: group.ID, Role: "member", Roles: []string{"member"}, Grants: []string{"directory.read", "message.send", "message.ask", "message.reply", "message.receive"}, Status: store.MembershipStatusActive})
	if err != nil {
		return err
	}
	fmt.Println(`{"status":"G2_SECOND_MEMBERSHIP_AUTHORIZED"}`)
	return nil
}

func revokeG2(raw []string) error {
	db, root, err := args("g2-revoke", raw)
	if err != nil {
		return err
	}
	meta, err := readFixture(root)
	if err != nil || meta.Scenario != "g2-g3" {
		return errors.New("G2 owned scenario required")
	}
	wire, err := os.ReadFile(filepath.Join(root, "g2-link.json"))
	if err != nil || len(wire) > 4096 {
		return errors.New("G2 Link record missing")
	}
	var record struct {
		LinkID string `json:"link_id"`
	}
	if json.Unmarshal(wire, &record) != nil || record.LinkID == "" {
		return errors.New("G2 Link record invalid")
	}
	s, err := store.New(db)
	if err != nil {
		return err
	}
	defer s.Close()
	link, err := s.GetCommunicationLinkForOwner(record.LinkID, meta.OwnerID)
	if err != nil || link == nil {
		return errors.New("G2 current Link missing")
	}
	revoked, err := s.RevokeCommunicationLink(link.ID, meta.OwnerID, link.Version, "synthetic G2 exact revocation")
	if err != nil || revoked.State != store.CommunicationLinkRevoked {
		return errors.New("G2 Link revocation failed")
	}
	fmt.Println(`{"status":"G2_LINK_REVOKED_CALLER_DENIAL_NOT_YET_TESTED"}`)
	return nil
}

// The response must be authenticated and decrypted, not a public capabilities
// response or a locally fabricated database summary.
func queryControlSnapshot(client *http.Client, origin string, device *e2ee.Identity, hub e2ee.PublicIdentity,
	binding clientwire.Binding, sequence uint64) ([]byte, error) {
	if origin != "http://127.0.0.1:8787" || sequence == 0 {
		return nil, errors.New("owned Control origin and sequence required")
	}
	route := clientwire.Route{Version: clientwire.Version, Direction: clientwire.DirectionRequest,
		HubID: binding.HubID, OwnerID: binding.OwnerID, DeviceID: binding.DeviceID, SessionEpoch: binding.SessionEpoch,
		Sequence: sequence, OperationID: fmt.Sprintf("synthetic-g3-snapshot-%d", sequence), Operation: "status.snapshot",
		SenderKeyID: device.Public().ID, SenderKeyVersion: binding.DeviceKeyVersion, ReceiverKeyID: hub.ID, ReceiverKeyVersion: binding.HubKeyVersion}
	packet, err := clientwire.SealRequest(device, hub, binding, route, []byte(`{}`))
	if err != nil {
		return nil, err
	}
	request, err := http.NewRequest(http.MethodPost, origin+"/v2/client/rpc", bytes.NewReader(packet))
	if err != nil {
		return nil, err
	}
	request.Header.Set("Content-Type", "application/octet-stream")
	response, err := client.Do(request)
	if err != nil {
		return nil, errors.New("owned Control request failed")
	}
	defer response.Body.Close()
	wire, err := io.ReadAll(io.LimitReader(response.Body, 262145))
	if err != nil || len(wire) > 262144 || response.StatusCode != http.StatusOK {
		return nil, errors.New("owned encrypted Control response invalid")
	}
	opened, err := clientwire.OpenResponse(device, hub, binding, wire)
	if err != nil {
		return nil, errors.New("owned Control response authentication failed")
	}
	if opened.Route.Operation != "status.snapshot" || opened.Route.OperationID != route.OperationID {
		return nil, errors.New("owned Control response correlation mismatch")
	}
	return opened.Plaintext, nil
}

func controlSnapshot(raw []string) error {
	db, root, err := args("control-snapshot", raw)
	if err != nil {
		return err
	}
	meta, err := readFixture(root)
	if err != nil || meta.Scenario != "g2-g3" {
		return errors.New("G3 owned scenario required")
	}
	device, err := loadFixtureIdentity(root, "owner-private", "device.key")
	if err != nil {
		return err
	}
	// This is the distinct synthetic Client-Control identity, never the peer key.
	path := filepath.Join(filepath.Dir(db), "e2ee", "client-control-identity.json")
	info, err := os.Lstat(path)
	if err != nil || !info.Mode().IsRegular() || info.Mode().Perm() != 0600 {
		return errors.New("owned Control identity missing")
	}
	wire, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	hub, err := e2ee.UnmarshalIdentity(wire)
	if err != nil {
		return err
	}
	s, err := store.New(db)
	if err != nil {
		return err
	}
	registered, err := s.GetClientDevice(meta.OwnerID, meta.DeviceID)
	s.Close()
	if err != nil || registered == nil {
		return errors.New("owned Control device missing")
	}
	binding := clientwire.Binding{HubID: meta.HubID, OwnerID: meta.OwnerID, DeviceID: meta.DeviceID, SessionEpoch: registered.SessionEpoch, HubKeyVersion: 1, DeviceKeyVersion: registered.KeyVersion}
	client := &http.Client{Timeout: 5 * time.Second, Transport: &http.Transport{Proxy: nil, DisableKeepAlives: true, ForceAttemptHTTP2: false}, CheckRedirect: func(*http.Request, []*http.Request) error { return errors.New("owned Control redirect denied") }}
	plaintext, err := queryControlSnapshot(client, "http://127.0.0.1:8787", device, hub.Public(), binding, registered.LastRequestSeq+1)
	if err != nil {
		return err
	}
	linkWire, err := os.ReadFile(filepath.Join(root, "g2-link.json"))
	if err != nil || len(linkWire) > 4096 {
		return errors.New("G3 exact Endpoint receipt missing")
	}
	var linkRecord struct {
		EndpointID string `json:"source_endpoint_id"`
	}
	if json.Unmarshal(linkWire, &linkRecord) != nil || linkRecord.EndpointID == "" {
		return errors.New("G3 exact Endpoint receipt invalid")
	}
	if err := validateG3Snapshot(plaintext, meta, linkRecord.EndpointID); err != nil {
		return err
	}
	fmt.Println(`{"status":"G3_AUTHENTICATED_ENCRYPTED_STATUS_SNAPSHOT_MATCHED"}`)
	return nil
}

func validateG3Snapshot(plaintext []byte, meta fixture, expectedEndpoint string) error {
	var response struct {
		OK     bool `json:"ok"`
		Result struct {
			OwnerID string `json:"owner_principal_id"`
			Groups  []struct {
				ID string `json:"group_id"`
			} `json:"groups"`
			Endpoints []struct {
				ID     string   `json:"endpoint_id"`
				Thread string   `json:"native_session_id"`
				Groups []string `json:"group_ids"`
			} `json:"endpoints"`
			Nodes []struct {
				ID string `json:"node_id"`
			} `json:"nodes"`
		} `json:"result"`
	}
	if expectedEndpoint == "" || len(plaintext) > 65536 || json.Unmarshal(plaintext, &response) != nil || !response.OK || response.Result.OwnerID != meta.OwnerID {
		return errors.New("G3 typed owner snapshot mismatch")
	}
	groups := map[string]bool{}
	for _, g := range response.Result.Groups {
		if groups[g.ID] {
			return errors.New("G3 duplicate Group")
		}
		groups[g.ID] = true
	}
	if !groups[meta.GroupID] || !groups[meta.AliceSecondGroupID] || groups[meta.BobGroupID] {
		return errors.New("G3 exact owner Group visibility mismatch")
	}
	endpointMatch := false
	for _, ep := range response.Result.Endpoints {
		if ep.Thread == meta.ThreadB {
			return errors.New("G3 foreign Bob Endpoint visible")
		}
		if ep.Thread == meta.ThreadA {
			if ep.ID != expectedEndpoint {
				return errors.New("G3 original Endpoint identity changed")
			}
			if endpointMatch {
				return errors.New("G3 duplicate original A Endpoint")
			}
			endpointMatch = true
			survives := false
			for _, g := range ep.Groups {
				if g == meta.GroupID {
					return errors.New("G3 left Group membership survives")
				}
				if g == meta.AliceSecondGroupID {
					survives = true
				}
			}
			if !survives {
				return errors.New("G3 second Group membership missing")
			}
		}
	}
	nodeMatch := false
	for _, n := range response.Result.Nodes {
		if n.ID == meta.NodeB {
			return errors.New("G3 foreign Bob Node visible")
		}
		if n.ID == meta.NodeA {
			nodeMatch = true
		}
	}
	if !endpointMatch || !nodeMatch {
		return errors.New("G3 original Endpoint or Node absent")
	}
	return nil
}

// The separately pinned TLS build input registers its existing implementation.
// A plain tracked helper refuses TLS instead of pretending it was installed.
var nativeTLSBootstrap func([]string) error

func dispatchTLSBootstrap(raw []string) error {
	if nativeTLSBootstrap == nil {
		return errors.New("TLS bootstrap implementation not installed")
	}
	return nativeTLSBootstrap(raw)
}
