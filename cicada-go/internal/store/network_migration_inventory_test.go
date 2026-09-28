package store

import (
	"bytes"
	"crypto/sha256"
	"database/sql"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"hash"
	"math"
	"sort"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/cicada-ai/cicada/internal/e2ee"
)

type networkV34TableDigest struct {
	Count  int
	Digest string
}

type networkV34Column struct {
	Name       string `json:"name"`
	Type       string `json:"type"`
	NotNull    int    `json:"not_null"`
	Default    any    `json:"default"`
	PrimaryKey int    `json:"primary_key"`
}

type networkV34Cell struct {
	Type  string `json:"type"`
	Value any    `json:"value"`
}

// networkV34AddedTables derives the exclusion set from the migration registry,
// so this test snapshots every pre-v35 table even if future Network migrations
// add more tables.
func networkV34AddedTables() map[string]struct{} {
	added := make(map[string]struct{})
	for _, migration := range v2Migrations {
		if migration.Version <= 34 {
			continue
		}
		for _, object := range migration.Objects {
			added[object] = struct{}{}
		}
	}
	return added
}

func networkV34QuoteIdentifier(value string) string {
	return `"` + strings.ReplaceAll(value, `"`, `""`) + `"`
}

func networkV34EncodeCell(value any) (networkV34Cell, error) {
	switch typed := value.(type) {
	case nil:
		return networkV34Cell{Type: "null"}, nil
	case int64:
		return networkV34Cell{Type: "integer", Value: typed}, nil
	case float64:
		return networkV34Cell{Type: "real_bits", Value: strconv.FormatUint(math.Float64bits(typed), 16)}, nil
	case string:
		return networkV34Cell{Type: "text", Value: typed}, nil
	case []byte:
		return networkV34Cell{Type: "blob_base64", Value: base64.StdEncoding.EncodeToString(typed)}, nil
	default:
		return networkV34Cell{}, fmt.Errorf("unsupported SQLite cell type %T", value)
	}
}

func networkV34WriteFrame(destination hash.Hash, value []byte) {
	var size [8]byte
	binary.BigEndian.PutUint64(size[:], uint64(len(value)))
	_, _ = destination.Write(size[:])
	_, _ = destination.Write(value)
}

// snapshotNetworkV34Data hashes columns and all rows of every existing
// application table. It never prints row data. The sole group projection
// exception is groups.network_id, which v35 adds as an explicit migration
// column; table-level mutation of Group's other fields remains detectable.
func snapshotNetworkV34Data(t *testing.T, db *sql.DB, extraGroupColumns ...string) map[string]networkV34TableDigest {
	t.Helper()
	added := networkV34AddedTables()
	ignoredGroupColumns := map[string]bool{"network_id": true}
	for _, column := range extraGroupColumns {
		ignoredGroupColumns[column] = true
	}
	tables, err := db.Query(`SELECT name FROM sqlite_master
WHERE type='table' AND name NOT LIKE 'sqlite_%' ORDER BY name`)
	if err != nil {
		t.Fatal(err)
	}
	var names []string
	for tables.Next() {
		var name string
		if err := tables.Scan(&name); err != nil {
			tables.Close()
			t.Fatal(err)
		}
		if name == "schema_migrations_v2" {
			continue // v35 necessarily adds its own ledger row; <=v34 is checked below.
		}
		if _, isNew := added[name]; isNew {
			continue
		}
		names = append(names, name)
	}
	if err := tables.Err(); err != nil {
		tables.Close()
		t.Fatal(err)
	}
	if err := tables.Close(); err != nil {
		t.Fatal(err)
	}

	result := make(map[string]networkV34TableDigest, len(names)+1)
	for _, name := range names {
		columnRows, err := db.Query(`PRAGMA table_info(` + networkV34QuoteIdentifier(name) + `)`)
		if err != nil {
			t.Fatalf("inspect table %s: %v", name, err)
		}
		var columns []networkV34Column
		for columnRows.Next() {
			var sequence, notNull, primaryKey int
			var column, declaredType string
			var defaultValue any
			if err := columnRows.Scan(&sequence, &column, &declaredType, &notNull, &defaultValue, &primaryKey); err != nil {
				columnRows.Close()
				t.Fatalf("inspect columns for %s: %v", name, err)
			}
			if name == "groups" && ignoredGroupColumns[column] {
				continue
			}
			encodedDefault, err := networkV34EncodeCell(defaultValue)
			if err != nil {
				columnRows.Close()
				t.Fatalf("encode schema default in %s: %v", name, err)
			}
			columns = append(columns, networkV34Column{Name: column, Type: declaredType,
				NotNull: notNull, Default: encodedDefault, PrimaryKey: primaryKey})
		}
		if err := columnRows.Err(); err != nil {
			columnRows.Close()
			t.Fatalf("read columns for %s: %v", name, err)
		}
		if err := columnRows.Close(); err != nil {
			t.Fatalf("close columns for %s: %v", name, err)
		}
		if len(columns) == 0 {
			t.Fatalf("table %s has no snapshotted columns", name)
		}

		selected := make([]string, len(columns))
		for index, column := range columns {
			selected[index] = networkV34QuoteIdentifier(column.Name)
		}
		query := `SELECT ` + strings.Join(selected, ",") + ` FROM ` + networkV34QuoteIdentifier(name)
		rows, err := db.Query(query)
		if err != nil {
			t.Fatalf("read table %s: %v", name, err)
		}
		encodedRows := make([][]byte, 0)
		for rows.Next() {
			values := make([]any, len(columns))
			pointers := make([]any, len(columns))
			for index := range values {
				pointers[index] = &values[index]
			}
			if err := rows.Scan(pointers...); err != nil {
				rows.Close()
				t.Fatalf("read row from %s: %v", name, err)
			}
			cells := make([]networkV34Cell, len(values))
			for index, value := range values {
				cells[index], err = networkV34EncodeCell(value)
				if err != nil {
					rows.Close()
					t.Fatalf("encode row from %s: %v", name, err)
				}
			}
			encoded, err := json.Marshal(cells)
			if err != nil {
				rows.Close()
				t.Fatalf("encode row from %s: %v", name, err)
			}
			encodedRows = append(encodedRows, encoded)
		}
		if err := rows.Err(); err != nil {
			rows.Close()
			t.Fatalf("read table %s: %v", name, err)
		}
		if err := rows.Close(); err != nil {
			t.Fatalf("close table %s: %v", name, err)
		}
		sort.Slice(encodedRows, func(i, j int) bool { return bytes.Compare(encodedRows[i], encodedRows[j]) < 0 })

		digest := sha256.New()
		encodedColumns, err := json.Marshal(columns)
		if err != nil {
			t.Fatalf("encode schema for %s: %v", name, err)
		}
		networkV34WriteFrame(digest, encodedColumns)
		for _, row := range encodedRows {
			networkV34WriteFrame(digest, row)
		}
		result[name] = networkV34TableDigest{Count: len(encodedRows), Digest: hex.EncodeToString(digest.Sum(nil))}
	}

	ledger, err := snapshotNetworkV34Ledger(t, db)
	if err != nil {
		t.Fatal(err)
	}
	result["schema_migrations_v2[version<=34]"] = ledger
	return result
}

func snapshotNetworkV34Ledger(t *testing.T, db *sql.DB) (networkV34TableDigest, error) {
	t.Helper()
	rows, err := db.Query(`SELECT version,migration_id,description,checksum,state,attempts,
source_count,target_count,verification_json,started_at,applied_at,last_error,created_at,updated_at
FROM schema_migrations_v2 WHERE version<=34 ORDER BY version`)
	if err != nil {
		return networkV34TableDigest{}, err
	}
	defer rows.Close()
	digest := sha256.New()
	var count int
	for rows.Next() {
		var version, attempts int64
		var sourceCount, targetCount int64
		var values [12]string
		if err := rows.Scan(&version, &values[0], &values[1], &values[2], &values[3], &attempts,
			&sourceCount, &targetCount, &values[4], &values[5], &values[6], &values[7], &values[8], &values[9]); err != nil {
			return networkV34TableDigest{}, err
		}
		encoded, err := json.Marshal([]any{version, values[0], values[1], values[2], values[3], attempts,
			sourceCount, targetCount, values[4], values[5], values[6], values[7], values[8], values[9]})
		if err != nil {
			return networkV34TableDigest{}, err
		}
		networkV34WriteFrame(digest, encoded)
		count++
	}
	if err := rows.Err(); err != nil {
		return networkV34TableDigest{}, err
	}
	return networkV34TableDigest{Count: count, Digest: hex.EncodeToString(digest.Sum(nil))}, nil
}

func assertNetworkV34DataEqual(t *testing.T, before, after map[string]networkV34TableDigest) {
	t.Helper()
	if len(before) != len(after) {
		t.Fatalf("legacy table inventory changed: before=%d after=%d", len(before), len(after))
	}
	names := make([]string, 0, len(before))
	for name := range before {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		if before[name] != after[name] {
			t.Errorf("legacy table %s changed: before=%+v after=%+v", name, before[name], after[name])
		}
	}
}

type networkV35GroupRevision struct {
	NetworkID string
	Revision  int64
	Version   int64
	UpdatedAt string
}

func snapshotNetworkV35Groups(t *testing.T, db *sql.DB) map[string]networkV35GroupRevision {
	t.Helper()
	rows, err := db.Query(`SELECT id,network_id,revision,version,updated_at FROM groups ORDER BY id`)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	result := make(map[string]networkV35GroupRevision)
	for rows.Next() {
		var id string
		var state networkV35GroupRevision
		if err := rows.Scan(&id, &state.NetworkID, &state.Revision, &state.Version, &state.UpdatedAt); err != nil {
			t.Fatal(err)
		}
		result[id] = state
	}
	if err := rows.Err(); err != nil {
		t.Fatal(err)
	}
	return result
}

func assertNetworkV35GroupsUnchanged(t *testing.T, before, after map[string]networkV35GroupRevision) {
	t.Helper()
	if len(before) != len(after) {
		t.Fatalf("Group inventory changed: before=%d after=%d", len(before), len(after))
	}
	for id, want := range before {
		if got := after[id]; got != want {
			t.Fatalf("Group %s changed during mapping preparation: before=%+v after=%+v", id, want, got)
		}
	}
}

func assertNetworkV35GroupMappingChanges(t *testing.T, before, after map[string]networkV35GroupRevision, mapped []string, networkID string) {
	t.Helper()
	if len(before) != len(after) {
		t.Fatalf("Group inventory changed: before=%d after=%d", len(before), len(after))
	}
	allowed := make(map[string]bool, len(mapped))
	for _, id := range mapped {
		allowed[id] = true
	}
	for id, previous := range before {
		current, ok := after[id]
		if !ok {
			t.Fatalf("Group %s disappeared during mapping", id)
		}
		if !allowed[id] {
			if current != previous {
				t.Fatalf("unmapped Group %s changed during mapping: before=%+v after=%+v", id, previous, current)
			}
			continue
		}
		updatedAt, err := time.Parse(time.RFC3339Nano, current.UpdatedAt)
		previousUpdatedAt, previousErr := time.Parse(time.RFC3339Nano, previous.UpdatedAt)
		if current.NetworkID != networkID || current.Revision != previous.Revision+1 ||
			current.Version != previous.Version+1 || err != nil || previousErr != nil || updatedAt.Before(previousUpdatedAt) {
			t.Fatalf("mapped Group %s has unexpected allowed-column changes: before=%+v after=%+v", id, previous, current)
		}
	}
}

func readNetworkV35GroupRevision(t *testing.T, s *Store, groupID string) networkV35GroupRevision {
	t.Helper()
	var value networkV35GroupRevision
	if err := s.db.QueryRow(`SELECT network_id,revision,version,updated_at FROM groups WHERE id=?`, groupID).
		Scan(&value.NetworkID, &value.Revision, &value.Version, &value.UpdatedAt); err != nil {
		t.Fatalf("read Group revision: %v", err)
	}
	return value
}

func seedNetworkV35LinkTarget(t *testing.T, s *Store, ownerID string, ownerKeyID string, ownerIdentity *e2ee.Identity) (string, string, string, string) {
	t.Helper()
	const groupID = "migration_link_target_group"
	const principalID = "migration_link_target_principal"
	const endpointID = "migration_link_target_endpoint"
	const nodeID = "migration_link_target_node"
	if _, err := s.CreateGroup(Group{ID: groupID, OwnerPrincipalID: ownerID,
		TrustDomainID: ownerID, Name: groupID, State: GroupStateActive}); err != nil {
		t.Fatal(err)
	}
	principal, err := s.CreatePrincipal(Principal{ID: principalID, Kind: PrincipalKindAgent,
		OwnerID: ownerID, TrustDomainID: ownerID, Name: principalID, Status: PrincipalStatusActive})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.CreateMembership(Membership{PrincipalID: principal.ID, GroupID: groupID,
		Role: "member", Grants: []string{"message.ask", "message.reply"}}); err != nil {
		t.Fatal(err)
	}
	endpoint, err := s.UpsertEndpointV2(Endpoint{ID: endpointID, Name: endpointID, Harness: "codex",
		NativeSessionID: "native_" + endpointID, MachineID: nodeID, Owner: ownerID,
		Status: "online", PrincipalID: principal.ID, GroupID: groupID})
	if err != nil {
		t.Fatal(err)
	}
	binding, err := s.CreateSessionBinding(SessionBinding{EndpointID: endpoint.ID,
		PrincipalID: principal.ID, GroupID: groupID, NativeSessionID: endpoint.NativeSessionID,
		NodeID: nodeID})
	if err != nil {
		t.Fatal(err)
	}
	binding, err = s.AcquireSessionBindingLease(binding.ID, "migration_link_target_lease", binding.Epoch,
		time.Now().UTC().Add(time.Hour).Format(time.RFC3339Nano))
	if err != nil {
		t.Fatalf("acquire synthetic target binding lease (epoch=%d status=%q): %v", binding.Epoch, binding.Status, err)
	}
	bindLinkSealedSendTestNode(t, s, ownerID, nodeID)

	endpointIdentity, err := e2ee.NewIdentity()
	if err != nil {
		t.Fatal(err)
	}
	attestation, err := endpointIdentity.SignEndpointKeyAttestation(endpointID, principal.ID,
		nodeID, binding.ID, binding.Epoch)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.RegisterEndpointKeyCandidate(endpointID, principal.ID,
		binding.ID, binding.Epoch, attestation); err != nil {
		t.Fatal(err)
	}
	manifest, err := s.PreviewGroupEndpointKeyGrant(ownerID, groupID, endpointID, ownerKeyID,
		time.Now().UTC().Add(-time.Minute), time.Now().UTC().Add(time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	issuedAt, err := time.Parse(time.RFC3339Nano, manifest.IssuedAt)
	if err != nil {
		t.Fatal(err)
	}
	expiresAt, err := time.Parse(time.RFC3339Nano, manifest.ExpiresAt)
	if err != nil {
		t.Fatal(err)
	}
	proof, err := ownerIdentity.SignOwnerLinkKeyGrant(manifest.OwnerID, GroupEndpointKeyGrantOperation,
		manifest.Digest, manifest.CandidateBindingDigest, uint64(manifest.CandidateVersion),
		e2ee.OwnerLinkGrantSideSource, issuedAt, expiresAt)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.AcceptGroupEndpointKeyGrant(ownerID, groupID, endpointID, ownerKeyID, proof); err != nil {
		t.Fatal(err)
	}
	return groupID, principal.ID, endpoint.ID, binding.ID
}

func seedNetworkV35LinkOwnerGrants(t *testing.T, s *Store, f *userMonitorBroadcastFixture, targetGroup, targetEndpoint string) {
	t.Helper()
	hubID, err := s.GetClientHubID()
	if err != nil {
		t.Fatal(err)
	}
	targetIdentity, err := e2ee.NewIdentity()
	if err != nil {
		t.Fatal(err)
	}
	targetKey, err := s.RegisterOwnerApprovalKeyLocal(f.sealed.ownerID, targetIdentity.Public())
	if err != nil {
		t.Fatal(err)
	}
	expiresAt := time.Now().UTC().Add(time.Hour).Truncate(time.Second)
	link, err := s.ProposeCommunicationLink(CommunicationLinkProposal{
		SourceEndpointID: f.sealed.source.id, SourceGroupID: f.sealed.groupID,
		TargetEndpointID: targetEndpoint, TargetGroupID: targetGroup,
		ActorOwnerID: f.sealed.ownerID, Direction: "bidirectional",
		Actions: []string{"ask", "reply"}, DataScopes: []string{"benchmark.public_result"},
		TransportHubID: hubID, ExpiresAt: expiresAt.Format(time.RFC3339),
	})
	if err != nil {
		t.Fatal(err)
	}
	issuedAt := time.Now().UTC().Add(-time.Minute)
	sourceProof, err := f.sealed.owner.SignOwnerLinkGrant(f.sealed.ownerID, link.ID,
		link.ContractDigest, uint64(link.Version), e2ee.OwnerLinkGrantSideSource, issuedAt, expiresAt)
	if err != nil {
		t.Fatal(err)
	}
	targetProof, err := targetIdentity.SignOwnerLinkGrant(f.sealed.ownerID, link.ID,
		link.ContractDigest, uint64(link.Version), e2ee.OwnerLinkGrantSideTarget, issuedAt, expiresAt)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.RecordCommunicationLinkOwnerGrant(link.ID, CommunicationLinkGrantSource,
		f.sealed.ownerKeyID, sourceProof); err != nil {
		t.Fatal(err)
	}
	if _, err := s.RecordCommunicationLinkOwnerGrant(link.ID, CommunicationLinkGrantTarget,
		targetKey.KeyID, targetProof); err != nil {
		t.Fatal(err)
	}
}

func seedNetworkV35ExistingLedger(t *testing.T, f *userMonitorBroadcastFixture) (targetGroupID, pendingGroupID string) {
	s := f.sealed.store

	// Preserve a real owner-approved sealed Monitor dispatch with synthetic
	// body bytes; assertions and logs below contain only table counts/digests.
	body := []byte("synthetic v34 approved Monitor payload")
	prepared, _ := f.prepare(t, body)
	approved, _ := f.confirm(t, prepared, body, 1)
	if _, err := s.AuthorizeUserMonitorBroadcastV2Delivery(f.consumeInput(approved)); err != nil {
		t.Fatal(err)
	}

	// Persist a sealed REQUEST, a claim receipt, and its correlated REPLY.
	messageID, requestID := "migration_v34_sealed_request", "migration_v34_request"
	wire := f.sealed.seal(t, f.sealed.source, f.sealed.target, f.sealed.sourceNode.nodeCredential,
		messageID, "REQUEST", requestID, "")
	request, err := s.EnqueueSameGroupSealedV1Ask(SameGroupSealedV1Ask{
		NodeCredentialDigest: f.sealed.sourceNode.nodeCredential,
		GroupID:              f.sealed.groupID, SourceEndpointID: f.sealed.source.id,
		TargetEndpointID: f.sealed.target.id, MessageID: messageID, RequestID: requestID,
		IdempotencyKey: "migration_v34_request_idempotency", DataScope: SameGroupSealedV1DataScope,
		ExpiresAt: time.Now().UTC().Add(20 * time.Minute).Format(time.RFC3339Nano), Ciphertext: wire,
	})
	if err != nil || request.State != FabricRequestOpen {
		t.Fatalf("seed sealed request failed: err=%v", err)
	}
	claims, err := s.ClaimSameGroupSealedV1Inbox(f.sealed.targetNode.nodeCredential,
		sameGroupSealedV1ClaimInput(f.sealed.target, "migration-v34-consumer"))
	if err != nil || len(claims) != 1 {
		t.Fatalf("seed sealed claim failed: count=%d err=%v", len(claims), err)
	}
	if _, err := s.RecordRelayReceipt(RelayReceipt{AttemptID: claims[0].AttemptID,
		MessageID: claims[0].MessageID, Digest: claims[0].Digest,
		TargetEndpointID: f.sealed.target.id, BindingID: claims[0].BindingID,
		BindingEpoch: claims[0].BindingEpoch, Layer: RelayReceiptNodeReceived}); err != nil {
		t.Fatal(err)
	}
	_, reverse := f.sealed.peer(t, f.sealed.target, f.sealed.source, f.sealed.targetNode.nodeCredential)
	replyID := "migration_v34_sealed_reply"
	replyWire, err := e2ee.SealEndpointMessage(f.sealed.target.identity,
		f.sealed.source.identity.Public(), sameGroupSealedV1Context(reverse, replyID,
			"REPLY", requestID, messageID), []byte("synthetic sealed reply"), 1)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.EnqueueSameGroupSealedV1Reply(SameGroupSealedV1Reply{
		NodeCredentialDigest: f.sealed.targetNode.nodeCredential,
		RequestID:            requestID, MessageID: replyID, Ciphertext: replyWire,
	}); err != nil {
		t.Fatal(err)
	}

	// Keep legacy goal/approval and Artifact records populated alongside the
	// newer scoped Artifact and Task ledgers.
	machine, err := s.UpsertMachine("migration_v34_machine", "synthetic fixture",
		map[string]any{"fixture": true}, "available")
	if err != nil {
		t.Fatal(err)
	}
	goal, err := s.CreateGoal("migration_v34_goal", "synthetic migration fixture",
		"preserve all rows", "no external data", 50, machine.ID, "migration_v34_monitor", "/tmp/cicada-migration-v34")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.CreateWorkspace("workspace_migration_v34_goal", goal.ID,
		goal.Workspace, "goal", ""); err != nil {
		t.Fatal(err)
	}
	worker, err := s.CreateWorker("migration_v34_worker", goal.ID, machine.ID, "/tmp/migration-v34-response")
	if err != nil {
		t.Fatal(err)
	}
	approval, err := s.CreateApproval("migration_v34_approval", goal.ID, worker.ID,
		"synthetic-review", map[string]any{"decision": "preserve"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.ResolveApproval(approval.ID, "accept"); err != nil {
		t.Fatal(err)
	}
	artifact, err := s.CreateArtifact(Artifact{ID: "migration_v34_artifact", GoalID: goal.ID,
		WorkerID: worker.ID, Name: "synthetic-report", Path: "report.txt", Kind: "evidence",
		Digest: strings.Repeat("a", 64), Evidence: "synthetic migration fixture"})
	if err != nil {
		t.Fatal(err)
	}
	ref, err := s.CreateArtifactRefV2(ArtifactRefV2Input{ID: "migration_v34_artifact_ref",
		ArtifactID: artifact.ID, GroupID: f.sealed.groupID,
		ProducerPrincipalID: f.sealed.source.principal, ProducerEndpointID: f.sealed.source.id,
		Digest: strings.Repeat("a", 64), Scopes: []string{ArtifactRefV2ScopeMetadata, ArtifactRefV2ScopeSummary}})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.CreateArtifactRefV2Grant(ArtifactRefV2GrantInput{ID: "migration_v34_artifact_grant",
		ArtifactRefID: ref.ID, GranteeGroupID: f.sealed.groupID,
		GrantorPrincipalID: f.sealed.ownerID, Scopes: []string{ArtifactRefV2ScopeSummary}}); err != nil {
		t.Fatal(err)
	}

	task, err := s.CreateSharedTask(SharedTask{ID: "migration_v34_shared_task",
		GroupID: f.sealed.groupID, Objective: "synthetic task",
		AcceptanceCriteria: "preserved result"})
	if err != nil {
		t.Fatal(err)
	}
	ready, err := s.ReadySharedTask(task.ID, task.Revision, "migration_v34_reviewer")
	if err != nil {
		t.Fatal(err)
	}
	claimed, err := s.ClaimSharedTask(task.ID, ready.Revision, f.sealed.source.principal,
		f.sealed.source.id, "migration_v34_claim", 300)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.SubmitSharedTaskResult(task.ID, claimed.OwnerPrincipalID, claimed.OwnerEndpointID,
		claimed.OwnerEpoch, claimed.Revision, "synthetic task result", []string{"artifact:migration_v34_artifact_ref"}); err != nil {
		t.Fatal(err)
	}

	// Contact replay state, ratchet bytes, and a queued peer envelope are
	// synthetic, and are covered only by digests in failure output.
	remote, err := e2ee.NewIdentity()
	if err != nil {
		t.Fatal(err)
	}
	contact, err := s.CreateContact(Contact{ID: "migration_v34_contact",
		Label: "synthetic peer", Identity: remote.Public()})
	if err != nil {
		t.Fatal(err)
	}
	if err := s.AcceptContactSequence(contact.ID, 17); err != nil {
		t.Fatal(err)
	}
	if err := s.SavePeerSession(PeerSession{ContactID: contact.ID, Epoch: 2,
		RootKey: bytes.Repeat([]byte{0x11}, 32), SendChainKey: bytes.Repeat([]byte{0x22}, 32),
		ReceiveChainKey: bytes.Repeat([]byte{0x33}, 32), SendCount: 3, ReceiveCount: 4,
		PendingOffer: []byte("synthetic-pending-ratchet"), Status: "active"}); err != nil {
		t.Fatal(err)
	}
	if _, err := s.CreatePeerMessage(PeerMessage{ID: "migration_v34_peer_message",
		ContactID: contact.ID, Direction: "outbound", SenderID: "synthetic-local",
		RecipientID: contact.Identity.ID, Sequence: 18,
		Envelope: []byte(`{"ciphertext":"synthetic-only"}`), AAD: "synthetic-aad"}); err != nil {
		t.Fatal(err)
	}

	targetGroupID, _, _, _ = seedNetworkV35LinkTarget(t, s, f.sealed.ownerID,
		f.sealed.ownerKeyID, f.sealed.owner)
	seedNetworkV35LinkOwnerGrants(t, s, f, targetGroupID, "migration_link_target_endpoint")
	const pendingID = "migration_v34_explicit_pending_group"
	if _, err := s.CreateGroup(Group{ID: pendingID, OwnerPrincipalID: f.sealed.ownerID,
		TrustDomainID: f.sealed.ownerID, Name: pendingID, State: GroupStateActive}); err != nil {
		t.Fatal(err)
	}
	return targetGroupID, pendingID
}

func TestNetworkV34UpgradeInterruptionPreservesCompleteLedgerAndMappingScope(t *testing.T) {
	f := newUserMonitorBroadcastFixture(t)
	s := f.sealed.store
	targetGroupID, pendingGroupID := seedNetworkV35ExistingLedger(t, f)
	path := f.sealed.dbPath

	// Record the complete v34 application state: every non-Network table and
	// every row is included, not only a hand-picked set of table names.
	before := snapshotNetworkV34Data(t, s.db)
	nonempty := 0
	for _, item := range before {
		if item.Count > 0 {
			nonempty++
		}
	}
	for _, table := range []string{
		"principals", "groups", "memberships", "endpoint_group_memberships", "fabric_endpoints", "session_bindings",
		"owner_approval_keys_v2", "group_endpoint_key_grants_v2", "goals", "approvals", "contacts", "peer_sessions", "peer_messages",
		"communication_links_v2", "communication_link_grants_v2", "fabric_messages", "relay_v2_requests", "relay_v2_receipts",
		"relay_v2_message_security", "relay_v2_outbox", "artifacts", "artifact_v2_refs", "artifact_v2_grants",
		"shared_tasks_v2", "shared_task_v2_results", "user_monitor_broadcast_v2",
	} {
		if before[table].Count == 0 {
			t.Fatalf("synthetic v34 preservation fixture did not populate %s", table)
		}
	}
	t.Logf("synthetic v34 inventory: tables=%d nonempty_tables=%d; row bodies and keys are represented only by SHA-256 digests",
		len(before), nonempty)

	// Recreate a v34 database by removing only objects introduced after v34.
	for object := range networkV34AddedTables() {
		if _, err := s.db.Exec(`DROP TABLE IF EXISTS ` + networkV34QuoteIdentifier(object)); err != nil {
			t.Fatalf("form v34 schema by removing %s: %v", object, err)
		}
	}
	if _, err := s.db.Exec(`DROP INDEX IF EXISTS groups_network_idx`); err != nil {
		t.Fatal(err)
	}
	if _, err := s.db.Exec(`ALTER TABLE groups DROP COLUMN network_id`); err != nil {
		t.Fatalf("form v34 Group schema: %v", err)
	}
	if _, err := s.db.Exec(`DELETE FROM schema_migrations_v2 WHERE version>34`); err != nil {
		t.Fatal(err)
	}
	var highest int
	if err := s.db.QueryRow(`SELECT max(version) FROM schema_migrations_v2 WHERE state='applied'`).Scan(&highest); err != nil || highest != 34 {
		t.Fatalf("fixture is not v34: version=%d err=%v", highest, err)
	}
	assertNetworkV34DataEqual(t, before, snapshotNetworkV34Data(t, s.db))
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}

	// Fail after v35 DDL has run but before commit. The savepoint must roll
	// back the new objects and leave every v34 table/row and ledger entry intact.
	injected := errors.New("synthetic v35 migration interruption")
	failed, err := openStoreWithMigrationHook(path, func(migrationID, phase string) error {
		if migrationID == "v2.fabric.network_identity" && phase == "after_apply" {
			return injected
		}
		return nil
	})
	if failed != nil {
		_ = failed.Close()
	}
	if !errors.Is(err, injected) {
		t.Fatalf("v35 interruption result: %v", err)
	}
	check, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	check.SetMaxOpenConns(1)
	var phase string
	if err := check.QueryRow(`SELECT state FROM schema_migrations_v2 WHERE version=35`).Scan(&phase); err != nil || phase != v2MigrationFailed {
		t.Fatalf("v35 failed state=%q err=%v", phase, err)
	}
	var attempts int
	if err := check.QueryRow(`SELECT attempts FROM schema_migrations_v2 WHERE version=35`).Scan(&attempts); err != nil || attempts != 1 {
		t.Fatalf("v35 failed attempts=%d err=%v", attempts, err)
	}
	networkTables := make([]string, 0, len(networkV34AddedTables()))
	for table := range networkV34AddedTables() {
		networkTables = append(networkTables, table)
	}
	sort.Strings(networkTables)
	for _, table := range networkTables {
		var count int
		if err := check.QueryRow(`SELECT count(*) FROM sqlite_master WHERE type='table' AND name=?`, table).Scan(&count); err != nil || count != 0 {
			t.Fatalf("failed v35 left new Network table %s (count=%d): %v", table, count, err)
		}
	}
	var networkIndex, groupNetworkColumns int
	if err := check.QueryRow(`SELECT count(*) FROM sqlite_master WHERE type='index' AND name='groups_network_idx'`).Scan(&networkIndex); err != nil || networkIndex != 0 {
		t.Fatalf("failed v35 left Group Network index count=%d err=%v", networkIndex, err)
	}
	if err := check.QueryRow(`SELECT count(*) FROM pragma_table_info('groups') WHERE name='network_id'`).Scan(&groupNetworkColumns); err != nil || groupNetworkColumns != 0 {
		t.Fatalf("failed v35 left Group Network column count=%d err=%v", groupNetworkColumns, err)
	}
	assertNetworkV34DataEqual(t, before, snapshotNetworkV34Data(t, check))
	if err := check.Close(); err != nil {
		t.Fatal(err)
	}

	// A clean restart retries the failed version exactly once and applies v35.
	reopened, err := New(path)
	if err != nil {
		t.Fatalf("retry v34→v35 after interruption: %v", err)
	}
	defer reopened.Close()
	afterMigration := snapshotNetworkV34Data(t, reopened.db)
	assertNetworkV34DataEqual(t, before, afterMigration)
	entry, err := reopened.readV2Migration(35)
	if err != nil || entry == nil || entry.State != v2MigrationApplied || entry.Attempts != 2 {
		t.Fatalf("v35 did not retry exactly once: %+v err=%v", entry, err)
	}
	var groupNetwork string
	if err := reopened.db.QueryRow(`SELECT network_id FROM groups WHERE id=?`, f.sealed.groupID).Scan(&groupNetwork); err != nil || groupNetwork != "" {
		t.Fatalf("v35 assigned a legacy Group implicitly: network=%q err=%v", groupNetwork, err)
	}

	// Mapping preparation changes only the new mapping table. Approval may
	// change NetworkID, GroupRevision, row Version, and UpdatedAt on that exact
	// Group; every other historical table/column stays byte-for-byte equal.
	hubID, err := reopened.GetClientHubID()
	if err != nil {
		t.Fatal(err)
	}
	network, err := reopened.CreateNetwork(Network{ID: "migration_v35_network", HubID: hubID,
		Name: "synthetic migration network", OwnerID: f.sealed.ownerID})
	if err != nil {
		t.Fatal(err)
	}
	groupIDs := []string{f.sealed.groupID, targetGroupID}
	groupsBeforeMapping := snapshotNetworkV35Groups(t, reopened.db)
	preMap := make(map[string]networkV35GroupRevision, len(groupIDs))
	for _, groupID := range groupIDs {
		preMap[groupID] = readNetworkV35GroupRevision(t, reopened, groupID)
	}
	for _, groupID := range groupIDs {
		group := preMap[groupID]
		if _, err := reopened.PrepareGroupNetworkMapping(groupID, network.ID,
			"synthetic explicit decision", group.Version); err != nil {
			t.Fatalf("prepare mapping for %s: %v", groupID, err)
		}
		if got := readNetworkV35GroupRevision(t, reopened, groupID); got != group {
			t.Fatalf("prepare mutated Group %s: before=%+v after=%+v", groupID, group, got)
		}
	}
	mappingBaseline := snapshotNetworkV34Data(t, reopened.db, "revision", "version", "updated_at")
	assertNetworkV35GroupsUnchanged(t, groupsBeforeMapping, snapshotNetworkV35Groups(t, reopened.db))

	for _, groupID := range groupIDs {
		group := preMap[groupID]
		if err := reopened.ApproveGroupNetworkMapping(groupID, network.ID, group.Version); err != nil {
			t.Fatalf("approve mapping for %s: %v", groupID, err)
		}
		got := readNetworkV35GroupRevision(t, reopened, groupID)
		updatedAt, parseErr := time.Parse(time.RFC3339Nano, got.UpdatedAt)
		beforeUpdatedAt, beforeParseErr := time.Parse(time.RFC3339Nano, group.UpdatedAt)
		if got.NetworkID != network.ID || got.Revision != group.Revision+1 || got.Version != group.Version+1 ||
			parseErr != nil || beforeParseErr != nil || updatedAt.Before(beforeUpdatedAt) {
			t.Fatalf("approval changed unexpected Group revision fields for %s: before=%+v after=%+v", groupID, group, got)
		}
	}
	pendingBefore := readNetworkV35GroupRevision(t, reopened, pendingGroupID)
	if err := reopened.QuarantineGroupNetwork(pendingGroupID, "synthetic explicit pending decision", pendingBefore.Version); err != nil {
		t.Fatal(err)
	}
	if got := readNetworkV35GroupRevision(t, reopened, pendingGroupID); got != pendingBefore {
		t.Fatalf("pending quarantine changed Group row: before=%+v after=%+v", pendingBefore, got)
	}
	assertNetworkV35GroupMappingChanges(t, groupsBeforeMapping, snapshotNetworkV35Groups(t, reopened.db), groupIDs, network.ID)
	assertNetworkV34DataEqual(t, mappingBaseline, snapshotNetworkV34Data(t, reopened.db, "revision", "version", "updated_at"))

	var modeBefore string
	if err := reopened.db.QueryRow(`SELECT phase FROM network_mode_v2 WHERE id=1`).Scan(&modeBefore); err != nil || modeBefore != NetworkModePreparing {
		t.Fatalf("mode before activate=%q err=%v", modeBefore, err)
	}
	mapDigestBefore := networkV35MappingsDigest(t, reopened.db)
	groupsBeforeActivate := snapshotNetworkV35Groups(t, reopened.db)
	if err := reopened.ActivateNetworkMode(); err != nil {
		t.Fatalf("activate explicit migration: %v", err)
	}
	var modeAfter, activatedAt string
	if err := reopened.db.QueryRow(`SELECT phase,activated_at FROM network_mode_v2 WHERE id=1`).Scan(&modeAfter, &activatedAt); err != nil || modeAfter != NetworkModeActive || activatedAt == "" {
		t.Fatalf("activated mode=%q activated_at_present=%t err=%v", modeAfter, activatedAt != "", err)
	}
	mapDigestAfter := networkV35MappingsDigest(t, reopened.db)
	if mapDigestBefore != mapDigestAfter {
		t.Fatal("activation changed the approved/pending Group mapping ledger digest")
	}
	assertNetworkV35GroupsUnchanged(t, groupsBeforeActivate, snapshotNetworkV35Groups(t, reopened.db))
	assertNetworkV34DataEqual(t, mappingBaseline, snapshotNetworkV34Data(t, reopened.db, "revision", "version", "updated_at"))
}

func networkV35MappingsDigest(t *testing.T, db *sql.DB) string {
	t.Helper()
	rows, err := db.Query(`SELECT group_id,network_id,state,group_version FROM network_group_mappings_v2 ORDER BY group_id`)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	digest := sha256.New()
	for rows.Next() {
		var groupID, networkID, state string
		var groupVersion int64
		if err := rows.Scan(&groupID, &networkID, &state, &groupVersion); err != nil {
			t.Fatal(err)
		}
		encoded, err := json.Marshal([]any{groupID, networkID, state, groupVersion})
		if err != nil {
			t.Fatal(err)
		}
		networkV34WriteFrame(digest, encoded)
	}
	if err := rows.Err(); err != nil {
		t.Fatal(err)
	}
	return hex.EncodeToString(digest.Sum(nil))
}
