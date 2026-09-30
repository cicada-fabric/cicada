package server

import (
	"bytes"
	"crypto/sha256"
	"database/sql"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/cicada-ai/cicada/internal/e2ee"
	"github.com/cicada-ai/cicada/internal/fabric"
	"github.com/cicada-ai/cicada/internal/store"
)

type groupSpacesM2Endpoint struct {
	nodeID      string
	nativeID    string
	nodeToken   string
	joined      *fabric.JoinResult
	identity    *e2ee.Identity
	groupID     string
	defaultName string
}

func groupSpacesM2EndpointForTest(t *testing.T, db *store.Store, service *fabric.Service,
	groupID, nodeID, nativeID string) *groupSpacesM2Endpoint {
	t.Helper()
	nodeToken, nodeDigest, err := fabric.NewNodeCredential()
	if err != nil {
		t.Fatal(err)
	}
	bindRelayNodeTestCredential(t, db, nodeID, nodeDigest)
	joined, err := service.JoinForNodeCredential(nodeToken, fabric.JoinInput{
		GroupID: groupID, EndpointName: nativeID, Harness: "codex",
		NativeSessionID: nativeID, Workspace: "/synthetic/group-spaces-m2",
	})
	if err != nil {
		t.Fatalf("synthetic Node Group join failed: %v", err)
	}
	identity, err := e2ee.NewIdentity()
	if err != nil {
		t.Fatal(err)
	}
	return &groupSpacesM2Endpoint{nodeID: nodeID, nativeID: nativeID,
		nodeToken: nodeToken, joined: joined, identity: identity,
		groupID: groupID, defaultName: nativeID}
}

func groupSpacesM2SetMembershipGrants(t *testing.T, db *store.Store,
	endpoint *groupSpacesM2Endpoint, grants []string) {
	t.Helper()
	membership, err := db.GetMembershipByPrincipalGroup(endpoint.joined.Endpoint.PrincipalID, endpoint.groupID)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := db.UpdateMembershipAuthorization(membership.ID, membership.Roles,
		grants, membership.Authorization, membership.Version); err != nil {
		t.Fatalf("synthetic Group grants update failed: %v", err)
	}
}

func groupSpacesM2JoinNetwork(t *testing.T, db *store.Store, service *fabric.Service,
	ownerKey *e2ee.Identity, ownerID, hubID, networkID string, endpoint *groupSpacesM2Endpoint) {
	t.Helper()
	invitation := "synthetic-group-spaces-m2-invitation-" + endpoint.nativeID
	grants := []string{"directory.discover", "directory.publish"}
	if err := db.IssueNetworkInvitation(networkID, ownerID, ownerID, invitation,
		time.Now().UTC().Add(time.Hour).Format(time.RFC3339Nano), grants); err != nil {
		t.Fatal(err)
	}
	issued := time.Now().UTC().Add(-time.Minute)
	proof, err := ownerKey.SignOwnerNetworkJoinGrant(ownerID, hubID, networkID,
		endpoint.nodeID, endpoint.nativeID, store.NetworkInvitationDigest(invitation),
		ownerKey.Public().ID, grants, true, issued, time.Now().UTC().Add(time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := service.JoinNetworkForNodeCredential(endpoint.nodeToken, fabric.NetworkJoinInput{
		NetworkID: networkID, InvitationToken: invitation, OwnerJoinProof: string(proof),
		Harness: "codex", NativeSessionID: endpoint.nativeID, EndpointName: endpoint.defaultName,
	}); err != nil {
		t.Fatalf("synthetic Node Network join failed: %v", err)
	}
}

func groupSpacesM2GrantEndpointKey(t *testing.T, db *store.Store, ownerID string,
	ownerKey *e2ee.Identity, endpoint *groupSpacesM2Endpoint) {
	t.Helper()
	proof, err := endpoint.identity.SignEndpointKeyAttestation(endpoint.joined.Endpoint.ID,
		endpoint.joined.Endpoint.PrincipalID, endpoint.nodeID,
		endpoint.joined.BindingID, endpoint.joined.BindingEpoch)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := db.RegisterEndpointKeyCandidate(endpoint.joined.Endpoint.ID,
		endpoint.joined.Endpoint.PrincipalID, endpoint.joined.BindingID,
		endpoint.joined.BindingEpoch, proof); err != nil {
		t.Fatalf("synthetic Endpoint key candidate registration failed: %v", err)
	}
	manifest, err := db.PreviewGroupEndpointKeyGrant(ownerID, endpoint.groupID,
		endpoint.joined.Endpoint.ID, ownerKey.Public().ID,
		time.Now().UTC().Add(-time.Minute), time.Now().UTC().Add(time.Hour))
	if err != nil {
		t.Fatalf("synthetic Owner Group key manifest failed: %v", err)
	}
	issued, err := time.Parse(time.RFC3339Nano, manifest.IssuedAt)
	if err != nil {
		t.Fatal(err)
	}
	expires, err := time.Parse(time.RFC3339Nano, manifest.ExpiresAt)
	if err != nil {
		t.Fatal(err)
	}
	ownerProof, err := ownerKey.SignOwnerLinkKeyGrant(ownerID, store.GroupEndpointKeyGrantOperation,
		manifest.Digest, manifest.CandidateBindingDigest, uint64(manifest.CandidateVersion),
		e2ee.OwnerLinkGrantSideSource, issued, expires)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := db.AcceptGroupEndpointKeyGrant(ownerID, endpoint.groupID,
		endpoint.joined.Endpoint.ID, ownerKey.Public().ID, ownerProof); err != nil {
		t.Fatalf("synthetic Owner Group key grant failed: %v", err)
	}
}

func groupSpacesM2BindNodeForOwner(t *testing.T, db *store.Store, ownerID string,
	ownerKey *e2ee.Identity, nodeID string) string {
	t.Helper()
	ownerKeyRecord, err := db.RegisterOwnerApprovalKeyLocal(ownerID, ownerKey.Public())
	if err != nil {
		t.Fatal(err)
	}
	device, err := e2ee.NewIdentity()
	if err != nil {
		t.Fatal(err)
	}
	deviceID := "device-m2-" + nodeID
	hubID, err := db.GetClientHubID()
	if err != nil {
		t.Fatal(err)
	}
	deviceGrant, err := ownerKey.SignOwnerDeviceGrant(ownerID, deviceID, device.Public(),
		hubID, e2ee.OwnerDevicePurposeControl, time.Now().UTC().Add(-time.Minute),
		time.Now().UTC().Add(time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := db.RegisterClientDeviceFromOwnerGrant(store.RegisterClientDeviceInput{
		OwnerID: ownerID, OwnerKeyID: ownerKeyRecord.KeyID, DeviceID: deviceID,
		DevicePublic: device.Public(), OwnerDeviceGrant: deviceGrant,
	}); err != nil {
		t.Fatal(err)
	}
	nodeToken, nodeDigest, err := fabric.NewNodeCredential()
	if err != nil {
		t.Fatal(err)
	}
	code := sha256.Sum256([]byte("synthetic-group-spaces-m2-node-code-" + nodeID))
	codeDigest := hex.EncodeToString(code[:])
	if _, err := db.CreatePendingNodeDeviceBinding(nodeID, nodeID, nodeDigest,
		codeDigest, time.Now().UTC().Add(10*time.Minute)); err != nil {
		t.Fatal(err)
	}
	if _, err := db.ConfirmPendingNodeDeviceBinding(ownerID, deviceID, codeDigest); err != nil {
		t.Fatal(err)
	}
	return nodeToken
}

func groupSpacesM2EndpointForExternalHub(t *testing.T, db *store.Store,
	service *fabric.Service, ownerID, groupID, nodeID, nativeID string,
	ownerKey *e2ee.Identity) *groupSpacesM2Endpoint {
	t.Helper()
	nodeToken := groupSpacesM2BindNodeForOwner(t, db, ownerID, ownerKey, nodeID)
	joined, err := service.JoinForNodeCredential(nodeToken, fabric.JoinInput{
		GroupID: groupID, EndpointName: nativeID, Harness: "codex",
		NativeSessionID: nativeID, Workspace: "/synthetic/group-spaces-m2-docker",
	})
	if err != nil {
		t.Fatalf("synthetic disposable Hub Group join failed: %v", err)
	}
	identity, err := e2ee.NewIdentity()
	if err != nil {
		t.Fatal(err)
	}
	return &groupSpacesM2Endpoint{nodeID: nodeID, nativeID: nativeID,
		nodeToken: nodeToken, joined: joined, identity: identity,
		groupID: groupID, defaultName: nativeID}
}

func groupSpacesM2HTTPPost(t *testing.T, client *http.Client, baseURL string,
	endpoint *groupSpacesM2Endpoint, route string, input any, output any) (int, error) {
	t.Helper()
	encoded, err := json.Marshal(input)
	if err != nil {
		t.Fatal(err)
	}
	request, err := http.NewRequest(http.MethodPost, baseURL+route, bytes.NewReader(encoded))
	if err != nil {
		t.Fatal(err)
	}
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("Authorization", "CicadaNode "+endpoint.nodeToken)
	request.Header.Set("Cicada-Space-Session", "CicadaSession "+endpoint.joined.SessionToken)
	response, err := client.Do(request)
	if err != nil {
		return 0, err
	}
	defer response.Body.Close()
	const maxTestHTTPBody = 4 << 20
	body, err := io.ReadAll(io.LimitReader(response.Body, maxTestHTTPBody+1))
	if err != nil || len(body) > maxTestHTTPBody {
		return response.StatusCode, err
	}
	if response.StatusCode >= 200 && response.StatusCode < 300 && output != nil {
		if err := json.Unmarshal(body, output); err != nil {
			return response.StatusCode, err
		}
	}
	return response.StatusCode, nil
}

func groupSpacesM2Prepare(t *testing.T, client *http.Client, baseURL string,
	endpoint *groupSpacesM2Endpoint, input store.GroupSpacePrepareInput) *store.GroupSpaceSnapshot {
	t.Helper()
	var result store.GroupSpaceSnapshot
	status, err := groupSpacesM2HTTPPost(t, client, baseURL, endpoint,
		"/v2/fabric/node/spaces/prepare", input, &result)
	if err != nil || status != http.StatusOK {
		t.Fatalf("Group Space prepare failed: status=%d err=%v", status, err)
	}
	return &result
}

func groupSpacesM2EnvelopeSet(t *testing.T, snapshot *store.GroupSpaceSnapshot,
	producer *groupSpacesM2Endpoint, plaintext []byte) []store.GroupSpaceReaderCiphertext {
	t.Helper()
	if len(snapshot.Readers) == 0 {
		t.Fatal("Group Space reservation has no readers")
	}
	producerContext := store.GroupSpaceReaderContext(*snapshot, snapshot.Readers[0])
	signedBody, err := e2ee.SignGroupSpaceBody(producer.identity, producerContext, plaintext)
	if err != nil {
		t.Fatalf("synthetic producer body signing failed: %v", err)
	}
	set := make([]store.GroupSpaceReaderCiphertext, 0, len(snapshot.Readers))
	for _, reader := range snapshot.Readers {
		readerContext := store.GroupSpaceReaderContext(*snapshot, reader)
		wire, err := e2ee.SealGroupSpaceReader(producer.identity, reader.PublicIdentity,
			readerContext, signedBody, uint64(snapshot.Sequence))
		if err != nil {
			t.Fatalf("synthetic per-reader sealing failed: %v", err)
		}
		set = append(set, store.GroupSpaceReaderCiphertext{
			EndpointID: reader.EndpointID, KeyID: reader.KeyID, Wire: wire,
		})
	}
	return set
}

func groupSpacesM2Commit(t *testing.T, client *http.Client, baseURL string,
	endpoint *groupSpacesM2Endpoint, input store.GroupSpaceCommitInput) *store.GroupSpaceRecord {
	t.Helper()
	var result store.GroupSpaceRecord
	status, err := groupSpacesM2HTTPPost(t, client, baseURL, endpoint,
		"/v2/fabric/node/spaces/commit", input, &result)
	if err != nil || status != http.StatusCreated {
		t.Fatalf("Group Space commit failed: status=%d err=%v", status, err)
	}
	return &result
}

func groupSpacesM2Get(t *testing.T, client *http.Client, baseURL string,
	endpoint *groupSpacesM2Endpoint, groupID, recordID string) (int, *store.GroupSpaceRecord, error) {
	t.Helper()
	var result store.GroupSpaceRecord
	status, err := groupSpacesM2HTTPPost(t, client, baseURL, endpoint,
		"/v2/fabric/node/spaces/get", store.GroupSpaceGetInput{
			GroupID: groupID, RecordID: recordID,
		}, &result)
	if err != nil {
		return status, nil, err
	}
	if status < 200 || status >= 300 {
		return status, nil, nil
	}
	return status, &result, nil
}

func groupSpacesM2Open(t *testing.T, record *store.GroupSpaceRecord,
	reader *groupSpacesM2Endpoint, expected []byte, historyManifestID string,
	expectedSigner e2ee.PublicIdentity) {
	t.Helper()
	if len(record.Snapshot.Readers) != 1 {
		t.Fatalf("reader projection exposed %d reader keys", len(record.Snapshot.Readers))
	}
	readerContext := store.GroupSpaceReaderContext(record.Snapshot,
		record.Snapshot.Readers[0])
	if historyManifestID != "" {
		readerContext.HistoryGrantID = historyManifestID
	}
	plaintext, _, err := e2ee.OpenGroupSpaceReader(reader.identity, expectedSigner,
		record.Snapshot.Producer.PublicIdentity, readerContext, record.ReaderCiphertext.Wire)
	if err != nil || !bytes.Equal(plaintext, expected) {
		t.Fatalf("reader could not verify and decrypt producer-signed body: err=%v", err)
	}
}

func TestGroupSpacesM2HTTPHistoryRetentionAndTopicCAS(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "group-spaces-m2.sqlite3")
	db, err := store.New(dbPath)
	if err != nil {
		t.Fatal(err)
	}
	currentDB := db
	t.Cleanup(func() {
		if currentDB != nil {
			_ = currentDB.Close()
		}
	})
	owner, err := db.CreatePrincipal(store.Principal{ID: "owner", Kind: store.PrincipalKindHuman,
		OwnerID: "owner", TrustDomainID: "m2-synthetic-domain", Name: "synthetic owner",
		Status: store.PrincipalStatusActive})
	if err != nil {
		t.Fatal(err)
	}
	group, err := db.CreateGroup(store.Group{Name: "synthetic M2 group",
		OwnerPrincipalID: owner.ID, TrustDomainID: owner.TrustDomainID,
		State: store.GroupStateActive})
	if err != nil {
		t.Fatal(err)
	}
	service, err := fabric.NewService(db, owner.ID, owner.TrustDomainID)
	if err != nil {
		t.Fatal(err)
	}
	writer := groupSpacesM2EndpointForTest(t, db, service, group.ID,
		"node-m2-writer", "native-m2-writer")
	reader := groupSpacesM2EndpointForTest(t, db, service, group.ID,
		"node-m2-reader", "native-m2-reader")
	lateReader := groupSpacesM2EndpointForTest(t, db, service, group.ID,
		"node-m2-late", "native-m2-late")

	// Give only the original writer and reader current Group Space read rights.
	for _, endpoint := range []*groupSpacesM2Endpoint{writer, reader} {
		membership, err := db.GetMembershipByPrincipalGroup(endpoint.joined.Endpoint.PrincipalID, group.ID)
		if err != nil {
			t.Fatal(err)
		}
		grants := append(append([]string(nil), membership.Grants...), "space.read", "space.write")
		if endpoint == writer {
			grants = append(grants, "space.moderate")
		}
		groupSpacesM2SetMembershipGrants(t, db, endpoint, grants)
	}

	ownerKey, err := e2ee.NewIdentity()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := db.RegisterOwnerApprovalKeyLocal(owner.ID, ownerKey.Public()); err != nil {
		t.Fatal(err)
	}
	hubID, err := db.GetClientHubID()
	if err != nil {
		t.Fatal(err)
	}
	networkID := "network_group_spaces_m2"
	if _, err := db.CreateNetwork(store.Network{ID: networkID, HubID: hubID,
		Name: "synthetic M2 network", OwnerID: owner.ID}); err != nil {
		t.Fatal(err)
	}
	if _, err := db.PrepareGroupNetworkMapping(group.ID, networkID,
		"synthetic M2 test mapping", group.Version); err != nil {
		t.Fatal(err)
	}
	if err := db.ApproveGroupNetworkMapping(group.ID, networkID, group.Version); err != nil {
		t.Fatal(err)
	}
	for _, endpoint := range []*groupSpacesM2Endpoint{writer, reader, lateReader} {
		groupSpacesM2JoinNetwork(t, db, service, ownerKey, owner.ID, hubID, networkID, endpoint)
	}
	if err := db.ActivateNetworkMode(); err != nil {
		t.Fatal(err)
	}
	for _, endpoint := range []*groupSpacesM2Endpoint{writer, reader, lateReader} {
		groupSpacesM2GrantEndpointKey(t, db, owner.ID, ownerKey, endpoint)
	}

	hub := httptest.NewServer(NewFabricHandler(service, "synthetic-operator-token"))
	client := hub.Client()
	firstPlaintext := []byte("synthetic-private-body-alpha-01")
	firstInput := store.GroupSpacePrepareInput{GroupID: group.ID,
		OperationID: "m2-operation-journal-001", Kind: store.GroupSpaceKindJournal,
		RetentionClass: "standard"}
	firstSnapshot := groupSpacesM2Prepare(t, client, hub.URL, writer, firstInput)
	readerIDs := make(map[string]bool, len(firstSnapshot.Readers))
	for _, item := range firstSnapshot.Readers {
		readerIDs[item.EndpointID] = true
	}
	if len(readerIDs) != 2 || !readerIDs[writer.joined.Endpoint.ID] ||
		!readerIDs[reader.joined.Endpoint.ID] || readerIDs[lateReader.joined.Endpoint.ID] {
		t.Fatalf("first reservation did not freeze the exact initial audience (%d readers)", len(readerIDs))
	}
	firstAgain := groupSpacesM2Prepare(t, client, hub.URL, writer, firstInput)
	if firstAgain.ReservationID != firstSnapshot.ReservationID || firstAgain.RecordID != firstSnapshot.RecordID {
		t.Fatal("Group Space prepare retry allocated a new reservation")
	}
	firstWires := groupSpacesM2EnvelopeSet(t, firstSnapshot, writer, firstPlaintext)
	firstCommit := store.GroupSpaceCommitInput{ReservationID: firstSnapshot.ReservationID,
		ReaderCiphertexts: firstWires}
	badWires := append([]store.GroupSpaceReaderCiphertext(nil), firstWires...)
	badWires[0].Wire = append([]byte(nil), badWires[0].Wire...)
	badWires[0].Wire[len(badWires[0].Wire)-1] ^= 1
	badStatus, badErr := groupSpacesM2HTTPPost(t, client, hub.URL, writer,
		"/v2/fabric/node/spaces/commit", store.GroupSpaceCommitInput{
			ReservationID: firstSnapshot.ReservationID, ReaderCiphertexts: badWires,
		}, nil)
	if badErr != nil || badStatus != http.StatusConflict {
		t.Fatalf("tampered per-reader ciphertext was accepted: status=%d err=%v", badStatus, badErr)
	}

	// The real Hub commits over TCP, but the relay drops the successful reply.
	// The exact ciphertext bytes are retried after closing and reopening SQLite.
	upstreamStatus := make(chan int, 1)
	dropReply := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		forward, err := http.NewRequestWithContext(r.Context(), r.Method,
			hub.URL+r.URL.RequestURI(), r.Body)
		if err != nil {
			upstreamStatus <- 0
			return
		}
		forward.Header = r.Header.Clone()
		upstream, err := http.DefaultClient.Do(forward)
		if err != nil {
			upstreamStatus <- 0
		} else {
			_, _ = io.Copy(io.Discard, upstream.Body)
			_ = upstream.Body.Close()
			upstreamStatus <- upstream.StatusCode
		}
		if hijacker, ok := w.(http.Hijacker); ok {
			connection, _, err := hijacker.Hijack()
			if err == nil {
				_ = connection.Close()
			}
		}
	}))
	_, lostReplyErr := groupSpacesM2HTTPPost(t, dropReply.Client(), dropReply.URL,
		writer, "/v2/fabric/node/spaces/commit", firstCommit, nil)
	if lostReplyErr == nil {
		t.Fatal("synthetic reply-dropping proxy returned a successful response")
	}
	if status := <-upstreamStatus; status != http.StatusCreated {
		t.Fatalf("reply-dropping proxy did not observe the durable Hub commit: status=%d", status)
	}
	dropReply.Close()
	hub.Close()
	if err := currentDB.Close(); err != nil {
		t.Fatal(err)
	}
	currentDB = nil
	db, err = store.New(dbPath)
	if err != nil {
		t.Fatal(err)
	}
	currentDB = db
	service, err = fabric.NewService(db, owner.ID, owner.TrustDomainID)
	if err != nil {
		t.Fatal(err)
	}
	hub = httptest.NewServer(NewFabricHandler(service, "synthetic-operator-token"))
	client = hub.Client()
	defer hub.Close()
	firstAfterRestart := groupSpacesM2Prepare(t, client, hub.URL, writer, firstInput)
	if firstAfterRestart.ReservationID != firstSnapshot.ReservationID || !firstAfterRestart.Committed {
		t.Fatal("Hub reopen did not preserve the committed prepare reservation")
	}
	firstRecord := groupSpacesM2Commit(t, client, hub.URL, writer, firstCommit)
	if firstRecord.CiphertextDigest == "" || firstRecord.Snapshot.RecordID != firstSnapshot.RecordID {
		t.Fatal("exact lost-reply retry did not return the original committed record")
	}
	var writerOriginalWire []byte
	for _, ciphertext := range firstCommit.ReaderCiphertexts {
		if ciphertext.EndpointID == writer.joined.Endpoint.ID {
			writerOriginalWire = ciphertext.Wire
			break
		}
	}
	if len(writerOriginalWire) == 0 {
		t.Fatal("producer self-envelope was missing from the immutable audience")
	}
	changedCiphertext := store.GroupSpaceCommitInput{ReservationID: firstCommit.ReservationID,
		ReaderCiphertexts: append([]store.GroupSpaceReaderCiphertext(nil), firstCommit.ReaderCiphertexts...)}
	changedCiphertext.ReaderCiphertexts[0].Wire = append([]byte(nil), changedCiphertext.ReaderCiphertexts[0].Wire...)
	changedCiphertext.ReaderCiphertexts[0].Wire[0] ^= 1
	changedStatus, changedErr := groupSpacesM2HTTPPost(t, client, hub.URL, writer,
		"/v2/fabric/node/spaces/commit", changedCiphertext, nil)
	if changedErr != nil || changedStatus != http.StatusConflict {
		t.Fatalf("changed ciphertext retry was accepted: status=%d err=%v", changedStatus, changedErr)
	}

	writerReadStatus, writerRead, err := groupSpacesM2Get(t, client, hub.URL, writer, group.ID, firstSnapshot.RecordID)
	if err != nil || writerReadStatus != http.StatusOK {
		t.Fatalf("producer self-read failed: status=%d err=%v", writerReadStatus, err)
	}
	groupSpacesM2Open(t, writerRead, writer, firstPlaintext, "", firstSnapshot.Producer.PublicIdentity)
	readerReadStatus, readerRead, err := groupSpacesM2Get(t, client, hub.URL, reader, group.ID, firstSnapshot.RecordID)
	if err != nil || readerReadStatus != http.StatusOK {
		t.Fatalf("original reader read failed: status=%d err=%v", readerReadStatus, err)
	}
	groupSpacesM2Open(t, readerRead, reader, firstPlaintext, "", firstSnapshot.Producer.PublicIdentity)
	lateOldStatus, _, err := groupSpacesM2Get(t, client, hub.URL, lateReader, group.ID, firstSnapshot.RecordID)
	if err != nil || lateOldStatus != http.StatusForbidden {
		t.Fatalf("late reader obtained pre-cutoff history: status=%d err=%v", lateOldStatus, err)
	}

	// Adding read permission starts the late reader at the next sequence. The
	// Owner key grant is refreshed against that new membership revision.
	lateMembership, err := db.GetMembershipByPrincipalGroup(lateReader.joined.Endpoint.PrincipalID, group.ID)
	if err != nil {
		t.Fatal(err)
	}
	lateGrants := append(append([]string(nil), lateMembership.Grants...), "space.read", "space.write")
	groupSpacesM2SetMembershipGrants(t, db, lateReader, lateGrants)
	groupSpacesM2GrantEndpointKey(t, db, owner.ID, ownerKey, lateReader)

	secondPlaintext := []byte("synthetic-private-body-beta-02")
	secondInput := store.GroupSpacePrepareInput{GroupID: group.ID,
		OperationID: "m2-operation-journal-002", Kind: store.GroupSpaceKindJournal,
		RetentionClass: "standard"}
	secondSnapshot := groupSpacesM2Prepare(t, client, hub.URL, writer, secondInput)
	if len(secondSnapshot.Readers) != 3 {
		t.Fatalf("new reader was not included in the next immutable audience: %d", len(secondSnapshot.Readers))
	}
	secondWires := groupSpacesM2EnvelopeSet(t, secondSnapshot, writer, secondPlaintext)
	secondRecord := groupSpacesM2Commit(t, client, hub.URL, writer,
		store.GroupSpaceCommitInput{ReservationID: secondSnapshot.ReservationID, ReaderCiphertexts: secondWires})
	if secondRecord.CiphertextDigest == "" {
		t.Fatal("second Group Space commit did not return a ciphertext digest")
	}
	lateNewStatus, lateNewRecord, err := groupSpacesM2Get(t, client, hub.URL, lateReader, group.ID, secondSnapshot.RecordID)
	if err != nil || lateNewStatus != http.StatusOK {
		t.Fatalf("late reader could not read post-cutoff record: status=%d err=%v", lateNewStatus, err)
	}
	groupSpacesM2Open(t, lateNewRecord, lateReader, secondPlaintext, "", secondSnapshot.Producer.PublicIdentity)
	lateOldStatus, _, err = groupSpacesM2Get(t, client, hub.URL, lateReader, group.ID, firstSnapshot.RecordID)
	if err != nil || lateOldStatus != http.StatusForbidden {
		t.Fatalf("late reader gained old history merely by joining: status=%d err=%v", lateOldStatus, err)
	}

	var page store.GroupSpacePage
	pageStatus, err := groupSpacesM2HTTPPost(t, client, hub.URL, writer,
		"/v2/fabric/node/spaces/list", store.GroupSpaceListInput{GroupID: group.ID,
			Limit: 1, Kind: store.GroupSpaceKindJournal}, &page)
	if err != nil || pageStatus != http.StatusOK || len(page.Records) != 1 || page.NextCursor == "" {
		t.Fatalf("bounded Group Space page omitted its continuation cursor: status=%d count=%d err=%v",
			pageStatus, len(page.Records), err)
	}
	crossEndpointStatus, crossEndpointErr := groupSpacesM2HTTPPost(t, client, hub.URL, reader,
		"/v2/fabric/node/spaces/list", store.GroupSpaceListInput{GroupID: group.ID,
			Limit: 1, Kind: store.GroupSpaceKindJournal, Cursor: page.NextCursor}, &store.GroupSpacePage{})
	if crossEndpointErr != nil || crossEndpointStatus != http.StatusBadRequest {
		t.Fatalf("cursor crossed Endpoint scope: status=%d err=%v", crossEndpointStatus, crossEndpointErr)
	}
	cursorJSON, err := base64.RawURLEncoding.DecodeString(page.NextCursor)
	if err != nil {
		t.Fatal(err)
	}
	var cursorClaims map[string]any
	if err := json.Unmarshal(cursorJSON, &cursorClaims); err != nil {
		t.Fatal(err)
	}
	cursorClaims["g"] = "grp_forged_group_scope"
	tamperedCursorJSON, err := json.Marshal(cursorClaims)
	if err != nil {
		t.Fatal(err)
	}
	tamperedCursor := base64.RawURLEncoding.EncodeToString(tamperedCursorJSON)
	tamperedCursorStatus, tamperedCursorErr := groupSpacesM2HTTPPost(t, client, hub.URL, writer,
		"/v2/fabric/node/spaces/list", store.GroupSpaceListInput{GroupID: group.ID,
			Limit: 1, Kind: store.GroupSpaceKindJournal, Cursor: tamperedCursor}, &store.GroupSpacePage{})
	if tamperedCursorErr != nil || tamperedCursorStatus != http.StatusBadRequest {
		t.Fatalf("tampered cursor crossed Group scope: status=%d err=%v", tamperedCursorStatus, tamperedCursorErr)
	}

	// Revoke and rejoin the original reader. Current Guard blocks the revoked
	// session; restored read permission starts a fresh history cutoff.
	if _, err := db.RevokeMembershipForPrincipalGroup(reader.joined.Endpoint.PrincipalID,
		group.ID, "synthetic M2 access revocation"); err != nil {
		t.Fatal(err)
	}
	revokedStatus, _, err := groupSpacesM2Get(t, client, hub.URL, reader, group.ID, secondSnapshot.RecordID)
	if err != nil || revokedStatus != http.StatusUnauthorized {
		t.Fatalf("revoked reader retained current access: status=%d err=%v", revokedStatus, err)
	}
	if _, err := db.CreateMembership(store.Membership{PrincipalID: reader.joined.Endpoint.PrincipalID,
		GroupID: group.ID, Role: "member", Roles: []string{"member"},
		Grants: []string{"directory.read", "message.send", "message.ask", "message.reply",
			"message.receive", "artifact.read", "space.read", "space.write"},
		Status: store.MembershipStatusActive}); err != nil {
		t.Fatalf("synthetic reader rejoin failed: %v", err)
	}
	rejoined, err := service.JoinForNodeCredential(reader.nodeToken, fabric.JoinInput{
		GroupID: group.ID, EndpointName: reader.defaultName, Harness: "codex",
		NativeSessionID: reader.nativeID, Workspace: "/synthetic/group-spaces-m2-rejoin",
	})
	if err != nil {
		t.Fatalf("synthetic trusted Group session rejoin failed: %v", err)
	}
	reader.joined = rejoined
	groupSpacesM2GrantEndpointKey(t, db, owner.ID, ownerKey, reader)
	for _, recordID := range []string{firstSnapshot.RecordID, secondSnapshot.RecordID} {
		status, _, err := groupSpacesM2Get(t, client, hub.URL, reader, group.ID, recordID)
		if err != nil || status != http.StatusForbidden {
			t.Fatalf("rejoined reader crossed the default history cutoff: status=%d err=%v", status, err)
		}
	}
	thirdPlaintext := []byte("synthetic-private-body-gamma-03")
	thirdInput := store.GroupSpacePrepareInput{GroupID: group.ID,
		OperationID: "m2-operation-journal-003", Kind: store.GroupSpaceKindJournal,
		RetentionClass: "standard"}
	thirdSnapshot := groupSpacesM2Prepare(t, client, hub.URL, writer, thirdInput)
	thirdWires := groupSpacesM2EnvelopeSet(t, thirdSnapshot, writer, thirdPlaintext)
	_ = groupSpacesM2Commit(t, client, hub.URL, writer,
		store.GroupSpaceCommitInput{ReservationID: thirdSnapshot.ReservationID, ReaderCiphertexts: thirdWires})
	readerCurrentStatus, readerCurrent, err := groupSpacesM2Get(t, client, hub.URL, reader, group.ID, thirdSnapshot.RecordID)
	if err != nil || readerCurrentStatus != http.StatusOK {
		t.Fatalf("rejoined reader could not read new sequence: status=%d err=%v", readerCurrentStatus, err)
	}
	groupSpacesM2Open(t, readerCurrent, reader, thirdPlaintext, "", thirdSnapshot.Producer.PublicIdentity)

	// The positive history grant is exact, Owner-signed and separately sealed.
	var historyManifest store.GroupSpaceHistoryManifest
	historyManifestStatus, historyManifestErr := groupSpacesM2HTTPPost(t, client, hub.URL, writer,
		"/v2/fabric/node/spaces/history/manifest", store.GroupSpaceHistoryManifestInput{
			GroupID: group.ID, RecordID: firstSnapshot.RecordID,
			RecipientEndpointID: reader.joined.Endpoint.ID, OwnerKeyID: ownerKey.Public().ID,
		}, &historyManifest)
	if historyManifestErr != nil || historyManifestStatus != http.StatusOK {
		t.Fatalf("history grant manifest request failed: status=%d err=%v", historyManifestStatus, historyManifestErr)
	}
	var writerEvidence store.GroupSpaceEndpointEvidence
	for _, evidence := range firstSnapshot.Readers {
		if evidence.EndpointID == writer.joined.Endpoint.ID {
			writerEvidence = evidence
			break
		}
	}
	if writerEvidence.EndpointID == "" {
		t.Fatal("producer evidence was missing from the immutable audience")
	}
	_, originalSignedBody, err := e2ee.OpenGroupSpaceReader(writer.identity,
		firstSnapshot.Producer.PublicIdentity, firstSnapshot.Producer.PublicIdentity,
		store.GroupSpaceReaderContext(*firstSnapshot, writerEvidence),
		writerOriginalWire)
	if err != nil {
		t.Fatalf("original producer-signed body could not be opened for authorized rewrap: %v", err)
	}
	historyProof, err := ownerKey.SignGroupSpaceHistoryGrant(historyManifest.Grant)
	if err != nil {
		t.Fatal(err)
	}
	historyContext := store.GroupSpaceHistoryReaderContext(historyManifest.Original.Snapshot,
		historyManifest.Recipient, historyManifest.Grant.ManifestID)
	historyWire, err := e2ee.SealGroupSpaceReader(writer.identity,
		historyManifest.Recipient.PublicIdentity, historyContext,
		originalSignedBody, uint64(firstSnapshot.Sequence))
	if err != nil {
		t.Fatalf("history envelope sealing failed: %v", err)
	}
	historyCommit := store.GroupSpaceHistoryCommitInput{ManifestID: historyManifest.Grant.ManifestID,
		OwnerProof: historyProof, ReaderCiphertext: store.GroupSpaceReaderCiphertext{
			EndpointID: historyManifest.Recipient.EndpointID,
			KeyID:      historyManifest.Recipient.KeyID, Wire: historyWire,
		}}
	var forgedGrant e2ee.GroupSpaceHistoryGrant
	if err := json.Unmarshal(historyProof, &forgedGrant); err != nil {
		t.Fatal(err)
	}
	forgedGrant.Signature[0] ^= 1
	forgedProof, err := json.Marshal(forgedGrant)
	if err != nil {
		t.Fatal(err)
	}
	forgedCommit := historyCommit
	forgedCommit.OwnerProof = forgedProof
	forgedStatus, forgedErr := groupSpacesM2HTTPPost(t, client, hub.URL, writer,
		"/v2/fabric/node/spaces/history/grant", forgedCommit, nil)
	if forgedErr != nil || forgedStatus != http.StatusForbidden {
		t.Fatalf("forged Owner history approval was accepted: status=%d err=%v", forgedStatus, forgedErr)
	}
	var historyCommitResult store.GroupSpaceRecord
	historyStatus, historyErr := groupSpacesM2HTTPPost(t, client, hub.URL, writer,
		"/v2/fabric/node/spaces/history/grant", historyCommit, &historyCommitResult)
	if historyErr != nil || historyStatus != http.StatusCreated {
		t.Fatalf("valid Owner history grant was rejected: status=%d err=%v", historyStatus, historyErr)
	}
	historicalStatus, historicalRecord, err := groupSpacesM2Get(t, client, hub.URL,
		reader, group.ID, firstSnapshot.RecordID)
	if err != nil || historicalStatus != http.StatusOK {
		t.Fatalf("Owner-granted historical reader could not fetch original record: status=%d err=%v", historicalStatus, err)
	}
	groupSpacesM2Open(t, historicalRecord, reader, firstPlaintext,
		historyManifest.Grant.ManifestID, historyManifest.Resharer.PublicIdentity)
	if !bytes.Equal(historicalRecord.Snapshot.Producer.Grant.SignedProof,
		firstSnapshot.Producer.Grant.SignedProof) {
		t.Fatal("history rewrap replaced the original producer Owner key proof")
	}

	// Topic records use optimistic status versions. One of two concurrent
	// version-1 status reservations may commit; the stale second CAS is denied.
	topicPlaintext := []byte("synthetic-private-topic-delta-04")
	topicSnapshot := groupSpacesM2Prepare(t, client, hub.URL, writer,
		store.GroupSpacePrepareInput{GroupID: group.ID, OperationID: "m2-operation-topic-001",
			Kind: store.GroupSpaceKindTopic, RetentionClass: "short"})
	topicWires := groupSpacesM2EnvelopeSet(t, topicSnapshot, writer, topicPlaintext)
	topicRecord := groupSpacesM2Commit(t, client, hub.URL, writer,
		store.GroupSpaceCommitInput{ReservationID: topicSnapshot.ReservationID, ReaderCiphertexts: topicWires})
	if topicRecord.TopicVersion != 1 || topicRecord.Snapshot.TopicID != topicSnapshot.RecordID {
		t.Fatal("new Topic did not begin at version 1")
	}
	statusInput := store.GroupSpacePrepareInput{GroupID: group.ID, OperationID: "m2-operation-topic-status-a",
		Kind: store.GroupSpaceKindTopicStatus, TopicID: topicSnapshot.RecordID,
		ExpectedTopicVersion: 1, Status: "RESOLVED", RetentionClass: "short"}
	statusSnapshot := groupSpacesM2Prepare(t, client, hub.URL, writer, statusInput)
	statusRetry := groupSpacesM2Prepare(t, client, hub.URL, writer, statusInput)
	if statusRetry.ReservationID != statusSnapshot.ReservationID {
		t.Fatal("Topic status operation retry allocated a second reservation")
	}
	staleStatusSnapshot := groupSpacesM2Prepare(t, client, hub.URL, writer,
		store.GroupSpacePrepareInput{GroupID: group.ID, OperationID: "m2-operation-topic-status-b",
			Kind: store.GroupSpaceKindTopicStatus, TopicID: topicSnapshot.RecordID,
			ExpectedTopicVersion: 1, Status: "RESOLVED", RetentionClass: "short"})
	statusWires := groupSpacesM2EnvelopeSet(t, statusSnapshot, writer, []byte("synthetic-topic-status-epsilon"))
	statusRecord := groupSpacesM2Commit(t, client, hub.URL, writer,
		store.GroupSpaceCommitInput{ReservationID: statusSnapshot.ReservationID, ReaderCiphertexts: statusWires})
	if statusRecord.TopicVersion != 2 {
		t.Fatal("Topic status CAS did not increment version")
	}
	staleWires := groupSpacesM2EnvelopeSet(t, staleStatusSnapshot, writer, []byte("synthetic-topic-status-zeta"))
	staleStatus, staleErr := groupSpacesM2HTTPPost(t, client, hub.URL, writer,
		"/v2/fabric/node/spaces/commit", store.GroupSpaceCommitInput{
			ReservationID: staleStatusSnapshot.ReservationID, ReaderCiphertexts: staleWires,
		}, nil)
	if staleErr != nil || staleStatus != http.StatusConflict {
		t.Fatalf("stale Topic version commit was accepted: status=%d err=%v", staleStatus, staleErr)
	}
	replyWiresSnapshot := groupSpacesM2Prepare(t, client, hub.URL, writer,
		store.GroupSpacePrepareInput{GroupID: group.ID, OperationID: "m2-operation-topic-reply-001",
			Kind: store.GroupSpaceKindReply, TopicID: topicSnapshot.RecordID, RetentionClass: "short"})
	replyWires := groupSpacesM2EnvelopeSet(t, replyWiresSnapshot, writer, []byte("synthetic-topic-reply-eta"))
	replyRecord := groupSpacesM2Commit(t, client, hub.URL, writer,
		store.GroupSpaceCommitInput{ReservationID: replyWiresSnapshot.ReservationID, ReaderCiphertexts: replyWires})
	if replyRecord.Snapshot.TopicID != topicSnapshot.RecordID {
		t.Fatal("Topic reply did not retain its parent topic scope")
	}
	for pageOrdinal := 0; pageOrdinal < 14; pageOrdinal++ {
		pageInput := store.GroupSpacePrepareInput{GroupID: group.ID,
			OperationID: fmt.Sprintf("m2-operation-page-%02d", pageOrdinal),
			Kind:        store.GroupSpaceKindJournal, RetentionClass: "standard"}
		pageSnapshot := groupSpacesM2Prepare(t, client, hub.URL, writer, pageInput)
		pageWires := groupSpacesM2EnvelopeSet(t, pageSnapshot, writer,
			[]byte(fmt.Sprintf("synthetic-page-body-%02d", pageOrdinal)))
		_ = groupSpacesM2Commit(t, client, hub.URL, writer,
			store.GroupSpaceCommitInput{ReservationID: pageSnapshot.ReservationID,
				ReaderCiphertexts: pageWires})
	}
	var boundedPage store.GroupSpacePage
	boundedStatus, boundedErr := groupSpacesM2HTTPPost(t, client, hub.URL, writer,
		"/v2/fabric/node/spaces/list", store.GroupSpaceListInput{GroupID: group.ID,
			Limit: store.GroupSpaceMaxPage + 1, Kind: store.GroupSpaceKindJournal}, &boundedPage)
	if boundedErr != nil || boundedStatus != http.StatusOK ||
		len(boundedPage.Records) != store.GroupSpaceMaxPage || boundedPage.NextCursor == "" {
		t.Fatalf("Group Space list did not clamp to the 16-record page boundary: status=%d count=%d err=%v",
			boundedStatus, len(boundedPage.Records), boundedErr)
	}

	// Force an expiry inside the disposable fixture (the production clock is
	// intentionally not injectable), then verify reader/history ciphertext and
	// public key snapshots are purged while only an ID tombstone remains.
	plaintexts := [][]byte{firstPlaintext, secondPlaintext, thirdPlaintext, topicPlaintext}
	checkDB, err := sql.Open("sqlite", dbPath)
	if err != nil {
		t.Fatal(err)
	}
	rows, err := checkDB.Query(`SELECT ciphertext FROM group_space_readers_v2 WHERE record_id=?`, firstSnapshot.RecordID)
	if err != nil {
		_ = checkDB.Close()
		t.Fatal(err)
	}
	for rows.Next() {
		var ciphertext []byte
		if err := rows.Scan(&ciphertext); err != nil {
			_ = rows.Close()
			_ = checkDB.Close()
			t.Fatal(err)
		}
		for _, plaintext := range plaintexts {
			if bytes.Contains(ciphertext, plaintext) {
				_ = rows.Close()
				_ = checkDB.Close()
				t.Fatal("Hub SQLite contained plaintext in a reader ciphertext column")
			}
		}
	}
	if err := rows.Close(); err != nil {
		_ = checkDB.Close()
		t.Fatal(err)
	}
	if _, err := checkDB.Exec(`UPDATE group_space_records_v2 SET expires_at=? WHERE record_id=?`,
		time.Now().UTC().Add(-time.Minute).Format(time.RFC3339Nano), firstSnapshot.RecordID); err != nil {
		_ = checkDB.Close()
		t.Fatal(err)
	}
	if err := checkDB.Close(); err != nil {
		t.Fatal(err)
	}
	purged, err := db.PurgeExpiredGroupSpaces(store.GroupSpaceMaxPage)
	if err != nil || purged < 1 {
		t.Fatalf("expired Group Space body was not purged: count=%d err=%v", purged, err)
	}
	purgedStatus, _, err := groupSpacesM2Get(t, client, hub.URL, writer, group.ID, firstSnapshot.RecordID)
	if err != nil || purgedStatus == http.StatusOK {
		t.Fatalf("purged Group Space body remained readable: status=%d err=%v", purgedStatus, err)
	}
	verifyDB, err := sql.Open("sqlite", dbPath)
	if err != nil {
		t.Fatal(err)
	}
	defer verifyDB.Close()
	for query, args := range map[string][]any{
		`SELECT COUNT(*) FROM group_space_readers_v2 WHERE record_id=?`:           {firstSnapshot.RecordID},
		`SELECT COUNT(*) FROM group_space_history_grants_v2 WHERE record_id=?`:    {firstSnapshot.RecordID},
		`SELECT COUNT(*) FROM group_space_history_manifests_v2 WHERE record_id=?`: {firstSnapshot.RecordID},
	} {
		var count int
		if err := verifyDB.QueryRow(query, args...).Scan(&count); err != nil || count != 0 {
			t.Fatalf("retention did not purge scoped ciphertext/key material: rows=%d err=%v", count, err)
		}
	}
	var tombstones int
	if err := verifyDB.QueryRow(`SELECT COUNT(*) FROM group_space_tombstones_v2 WHERE record_id=?`,
		firstSnapshot.RecordID).Scan(&tombstones); err != nil || tombstones != 1 {
		t.Fatalf("retention tombstone count=%d err=%v", tombstones, err)
	}
}

// TestGroupSpacesM2DockerHub bootstraps synthetic identities in the isolated
// StateDir mounted by test-client-hub-interop.sh, then exercises the actual
// disposable Hub process over TCP. It does not send management intent or
// planner operations and does not claim a native Harness session. A separate
// NewFabricHandler test proves the routes work with no Control object.
func TestGroupSpacesM2DockerHub(t *testing.T) {
	baseURL := os.Getenv("CICADA_TEST_HUB_URL")
	dbPath := os.Getenv("CICADA_TEST_HUB_DB")
	managerToken := os.Getenv("CICADA_TEST_HUB_TOKEN")
	if baseURL == "" || dbPath == "" || managerToken == "" {
		t.Skip("requires the isolated disposable Group Spaces M2 Docker Hub")
	}
	client := &http.Client{Timeout: 30 * time.Second}
	request, err := http.NewRequest(http.MethodGet, baseURL+"/v1/identity", nil)
	if err != nil {
		t.Fatal("create disposable Hub identity request")
	}
	request.Header.Set("Authorization", "Bearer "+managerToken)
	response, err := client.Do(request)
	if err != nil {
		t.Fatalf("read disposable Hub owner identity: %v", err)
	}
	var ownerIdentity e2ee.PublicIdentity
	if response.StatusCode != http.StatusOK || json.NewDecoder(response.Body).Decode(&ownerIdentity) != nil {
		_ = response.Body.Close()
		t.Fatalf("disposable Hub owner identity status=%d", response.StatusCode)
	}
	_ = response.Body.Close()
	if ownerIdentity.ID == "" {
		t.Fatal("disposable Hub owner identity was empty")
	}

	db, err := store.New(dbPath)
	if err != nil {
		t.Fatal("open only the disposable Hub StateDir for fixture setup")
	}
	ownerID := ownerIdentity.ID
	if err := db.EnsureLocalOwnerPrincipal(ownerID); err != nil {
		_ = db.Close()
		t.Fatal("ensure synthetic Hub owner principal")
	}
	ownerKey, err := e2ee.NewIdentity()
	if err != nil {
		_ = db.Close()
		t.Fatal("create synthetic Owner grant key")
	}
	if _, err := db.RegisterOwnerApprovalKeyLocal(ownerID, ownerKey.Public()); err != nil {
		_ = db.Close()
		t.Fatal("register synthetic Owner approval key")
	}
	group, err := db.CreateGroup(store.Group{Name: "synthetic M2 Docker Group",
		OwnerPrincipalID: ownerID, TrustDomainID: ownerID, State: store.GroupStateActive})
	if err != nil {
		_ = db.Close()
		t.Fatal("create synthetic Group in disposable Hub StateDir")
	}
	service, err := fabric.NewService(db, ownerID, ownerID)
	if err != nil {
		_ = db.Close()
		t.Fatal("create disposable Hub Fabric fixture")
	}
	writer := groupSpacesM2EndpointForExternalHub(t, db, service, ownerID,
		group.ID, "node-m2-docker-writer", "native-m2-docker-writer", ownerKey)
	reader := groupSpacesM2EndpointForExternalHub(t, db, service, ownerID,
		group.ID, "node-m2-docker-reader", "native-m2-docker-reader", ownerKey)
	for _, endpoint := range []*groupSpacesM2Endpoint{writer, reader} {
		membership, err := db.GetMembershipByPrincipalGroup(endpoint.joined.Endpoint.PrincipalID, group.ID)
		if err != nil {
			_ = db.Close()
			t.Fatal(err)
		}
		grants := append(append([]string(nil), membership.Grants...),
			"space.read", "space.write", "space.moderate")
		groupSpacesM2SetMembershipGrants(t, db, endpoint, grants)
	}
	hubID, err := db.GetClientHubID()
	if err != nil {
		_ = db.Close()
		t.Fatal("read disposable Hub identifier")
	}
	networkID := store.NewID("network_m2_docker")
	if _, err := db.CreateNetwork(store.Network{ID: networkID, HubID: hubID,
		Name: "synthetic M2 Docker Network", OwnerID: ownerID}); err != nil {
		_ = db.Close()
		t.Fatal("create synthetic Network in disposable Hub StateDir")
	}
	if _, err := db.PrepareGroupNetworkMapping(group.ID, networkID,
		"synthetic M2 Docker mapping", group.Version); err != nil {
		_ = db.Close()
		t.Fatal("prepare synthetic Group Network mapping")
	}
	if err := db.ApproveGroupNetworkMapping(group.ID, networkID, group.Version); err != nil {
		_ = db.Close()
		t.Fatal("approve synthetic Group Network mapping")
	}
	for _, endpoint := range []*groupSpacesM2Endpoint{writer, reader} {
		groupSpacesM2JoinNetwork(t, db, service, ownerKey, ownerID,
			hubID, networkID, endpoint)
	}
	if err := db.ActivateNetworkMode(); err != nil {
		_ = db.Close()
		t.Fatal("activate disposable fixture Network mode")
	}
	for _, endpoint := range []*groupSpacesM2Endpoint{writer, reader} {
		groupSpacesM2GrantEndpointKey(t, db, ownerID, ownerKey, endpoint)
	}
	if err := db.Close(); err != nil {
		t.Fatal("close fixture Store before Hub HTTP requests")
	}

	input := store.GroupSpacePrepareInput{GroupID: group.ID,
		OperationID: "m2-docker-journal-001", Kind: store.GroupSpaceKindJournal,
		RetentionClass: "standard"}
	snapshot := groupSpacesM2Prepare(t, client, baseURL, writer, input)
	if len(snapshot.Readers) != 2 {
		t.Fatalf("disposable Hub froze %d readers, want writer and reader", len(snapshot.Readers))
	}
	plaintext := []byte("synthetic-disposable-hub-private-journal-body")
	wires := groupSpacesM2EnvelopeSet(t, snapshot, writer, plaintext)
	committed := groupSpacesM2Commit(t, client, baseURL, writer,
		store.GroupSpaceCommitInput{ReservationID: snapshot.ReservationID, ReaderCiphertexts: wires})
	if committed.Snapshot.RecordID != snapshot.RecordID || committed.CiphertextDigest == "" {
		t.Fatal("disposable Hub did not persist the sealed journal")
	}
	for _, endpoint := range []*groupSpacesM2Endpoint{writer, reader} {
		status, record, err := groupSpacesM2Get(t, client, baseURL, endpoint, group.ID, snapshot.RecordID)
		if err != nil || status != http.StatusOK {
			t.Fatalf("disposable Hub scoped reader GET failed: status=%d err=%v", status, err)
		}
		groupSpacesM2Open(t, record, endpoint, plaintext, "", snapshot.Producer.PublicIdentity)
	}
	wrongNode := *reader
	wrongNode.nodeToken = writer.nodeToken
	wrongNodeStatus, wrongNodeErr := groupSpacesM2HTTPPost(t, client, baseURL, &wrongNode,
		"/v2/fabric/node/spaces/get", store.GroupSpaceGetInput{
			GroupID: group.ID, RecordID: snapshot.RecordID,
		}, &store.GroupSpaceRecord{})
	if wrongNodeErr != nil || wrongNodeStatus != http.StatusForbidden {
		t.Fatalf("disposable Hub accepted mismatched Node and Group Session: status=%d err=%v", wrongNodeStatus, wrongNodeErr)
	}

	topicInput := store.GroupSpacePrepareInput{GroupID: group.ID,
		OperationID: "m2-docker-topic-001", Kind: store.GroupSpaceKindTopic,
		RetentionClass: "short"}
	topicSnapshot := groupSpacesM2Prepare(t, client, baseURL, writer, topicInput)
	topicWires := groupSpacesM2EnvelopeSet(t, topicSnapshot, writer,
		[]byte("synthetic-disposable-hub-topic"))
	topicRecord := groupSpacesM2Commit(t, client, baseURL, writer,
		store.GroupSpaceCommitInput{ReservationID: topicSnapshot.ReservationID, ReaderCiphertexts: topicWires})
	if topicRecord.TopicVersion != 1 {
		t.Fatal("disposable Hub Topic did not start at version 1")
	}
	statusInput := store.GroupSpacePrepareInput{GroupID: group.ID,
		OperationID: "m2-docker-topic-status-a", Kind: store.GroupSpaceKindTopicStatus,
		TopicID: topicSnapshot.RecordID, ExpectedTopicVersion: 1,
		Status: "RESOLVED", RetentionClass: "short"}
	statusA := groupSpacesM2Prepare(t, client, baseURL, writer, statusInput)
	statusInput.OperationID = "m2-docker-topic-status-b"
	statusB := groupSpacesM2Prepare(t, client, baseURL, writer, statusInput)
	statusWires := groupSpacesM2EnvelopeSet(t, statusA, writer,
		[]byte("synthetic-disposable-topic-status"))
	if result := groupSpacesM2Commit(t, client, baseURL, writer, store.GroupSpaceCommitInput{
		ReservationID: statusA.ReservationID, ReaderCiphertexts: statusWires,
	}); result.TopicVersion != 2 {
		t.Fatal("disposable Hub Topic status did not commit version 2")
	}
	staleWires := groupSpacesM2EnvelopeSet(t, statusB, writer,
		[]byte("synthetic-stale-disposable-topic-status"))
	staleStatus, staleErr := groupSpacesM2HTTPPost(t, client, baseURL, writer,
		"/v2/fabric/node/spaces/commit", store.GroupSpaceCommitInput{
			ReservationID: statusB.ReservationID, ReaderCiphertexts: staleWires,
		}, nil)
	if staleErr != nil || staleStatus != http.StatusConflict {
		t.Fatalf("disposable Hub accepted a stale Topic status CAS: status=%d err=%v", staleStatus, staleErr)
	}
}
