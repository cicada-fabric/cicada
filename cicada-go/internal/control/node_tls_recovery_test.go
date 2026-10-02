package control

import (
	"bytes"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"reflect"
	"testing"
	"time"

	"github.com/cicada-ai/cicada/internal/e2ee"
	"github.com/cicada-ai/cicada/internal/fabric"
	"github.com/cicada-ai/cicada/internal/nodewire"
	"github.com/cicada-ai/cicada/internal/pqtls"
	"github.com/cicada-ai/cicada/internal/store"
)

func nodeTLSRecoveryNative(t *testing.T) bool {
	t.Helper()
	if err := pqtls.Available(); err != nil {
		if os.Getenv("PQTLS_TEST_OPENSSL") != "" {
			t.Fatal("native TLS recovery gate requested but adapter unavailable")
		}
		if !errors.Is(err, pqtls.ErrUnavailable) {
			t.Fatal(err)
		}
		t.Log("NOT_RUN native TLS recovery: typed unavailable; missing-current rejection remains covered")
		return false
	}
	return true
}

func nodeTLSRecoveryQuery(f controlTLSActivationFixture, origin string) nodewire.RecoveryRequest {
	return nodewire.RecoveryRequest{Nonce: bytes.Repeat([]byte{0x74}, 32), Origin: origin, CredentialDigest: f.digest, RestoreDigest: nodewire.RecoveryDigest([]byte("SYNTHETIC TLS RESTORE ONLY")), PlanDigest: nodewire.RecoveryDigest([]byte("SYNTHETIC READ-ONLY PLAN ONLY")), Operations: []nodewire.RecoveryOperationQuery{}}
}

func nodeTLSRecoverySeal(t *testing.T, f controlTLSActivationFixture, q nodewire.RecoveryRequest) []byte {
	t.Helper()
	p, err := nodewire.SealRecoveryRequest(f.node, nodeControlWireBinding(f.binding), q)
	if err != nil {
		t.Fatal("seal synthetic recovery request", err)
	}
	return p
}

func nodeTLSRecoveryActive(t *testing.T) (controlTLSActivationFixture, *store.NodeTLSAuthoritySnapshot) {
	t.Helper()
	f := newControlTLSActivationFixture(t)
	installed := controlTLSActivationInstalled(t, f)
	action := store.NodeTLSAuthorityActionInput{RequestID: installed.Claims.RequestID, NodeID: f.binding.NodeID, CredentialDigest: f.digest, ExpectedVersion: installed.RowVersion}
	claims, err := f.c.store.PrepareNodeTLSActivation(action, e2ee.NodeTLSAuthorityDigest([]byte("SYNTHETIC TLS RECOVERY ACTIVATION ONLY")))
	if err != nil {
		t.Fatal(err)
	}
	proof, err := e2ee.SignNodeTLSActivation(f.hub, claims)
	if err != nil {
		t.Fatal(err)
	}
	active, err := f.c.store.ActivateNodeTLSGrant(store.NodeTLSActivationInput{NodeTLSAuthorityActionInput: action, Activation: proof})
	if err != nil || active == nil || active.State != store.NodeTLSActive {
		t.Fatal("actual C-issued exact Owner-approved ACTIVE required", err)
	}
	return f, active
}

func nodeTLSRecoverySQL(t *testing.T, f controlTLSActivationFixture) *sql.DB {
	t.Helper()
	db, err := sql.Open("sqlite", f.path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	return db
}

func nodeTLSRecoveryExec(t *testing.T, db *sql.DB, query string, args ...any) {
	t.Helper()
	if _, err := db.Exec(query, args...); err != nil {
		t.Fatal("mutate disposable synthetic fixture", err)
	}
}

// Hash logical rows, including inbox ciphertext and permanent TLS evidence.
// Never print their bodies. WAL/checkpoint bytes are not a logical write oracle.
func nodeTLSRecoveryEvidence(t *testing.T, db *sql.DB) [32]byte {
	t.Helper()
	h := sha256.New()
	for _, table := range []string{"principals", "owner_approval_keys_v2", "client_devices_v2", "node_owner_bindings_v2", "fabric_node_credentials", "node_control_key_bindings_v1", "node_control_rpc_sequences_v1", "node_control_rpc_inbox_v1", "node_tls_authority_v1", "node_tls_epoch_floors_v1", "node_tls_issuer_serial_floors_v1", "node_tls_proof_nonces_v1", "node_tls_application_keys_v1"} {
		_, _ = h.Write([]byte(table + "\x00"))
		rows, err := db.Query(`SELECT * FROM ` + table + ` ORDER BY rowid`)
		if err != nil {
			t.Fatal("read synthetic evidence inventory", err)
		}
		columns, err := rows.Columns()
		if err != nil {
			rows.Close()
			t.Fatal(err)
		}
		for rows.Next() {
			values, targets := make([]any, len(columns)), make([]any, len(columns))
			for i := range values {
				targets[i] = &values[i]
			}
			if err := rows.Scan(targets...); err != nil {
				rows.Close()
				t.Fatal(err)
			}
			encoded, err := json.Marshal(values)
			if err != nil {
				rows.Close()
				t.Fatal(err)
			}
			_, _ = h.Write(encoded)
			_, _ = h.Write([]byte{0})
		}
		if err := rows.Err(); err != nil {
			rows.Close()
			t.Fatal(err)
		}
		rows.Close()
	}
	var digest [32]byte
	copy(digest[:], h.Sum(nil))
	return digest
}

func TestNodeTLSRecoveryPacketInputAndMissingCurrent(t *testing.T) {
	f := newControlTLSActivationFixture(t)
	q := nodeTLSRecoveryQuery(f, "http://127.0.0.1:8080")
	packet := nodeTLSRecoverySeal(t, f, q)
	for _, test := range []struct {
		name string
		s    *store.Store
		hub  *e2ee.Identity
		wire []byte
		want error
	}{
		{name: "nil_store", hub: f.hub, wire: packet, want: ErrNodeTLSCurrentUnavailable},
		{name: "nil_identity", s: f.c.store, wire: packet, want: ErrNodeTLSCurrentUnavailable},
		{name: "empty_packet", s: f.c.store, hub: f.hub, want: store.ErrNodeTLSAuthorityDenied},
		{name: "oversized_packet", s: f.c.store, hub: f.hub, wire: make([]byte, nodewire.MaxRecoveryPacketBytes+1), want: store.ErrNodeTLSAuthorityDenied},
		{name: "node_control_without_current_tls", s: f.c.store, hub: f.hub, wire: packet, want: ErrNodeTLSCurrentUnavailable},
	} {
		t.Run(test.name, func(t *testing.T) {
			if reply, err := ReadNodeTLSRecoveryPacket(test.s, test.hub, f.digest, f.binding.NodeID, test.wire); len(reply) != 0 || !errors.Is(err, test.want) {
				t.Fatal("missing current TLS or malformed input authorized recovery", err)
			}
		})
	}
}

func TestNodeTLSRecoveryPacketNativeExactCurrentReadOnlyBounded(t *testing.T) {
	if !nodeTLSRecoveryNative(t) {
		return
	}
	f, active := nodeTLSRecoveryActive(t)
	db := nodeTLSRecoverySQL(t, f)
	q := nodeTLSRecoveryQuery(f, active.Claims.ApplicationOrigin)
	states := []string{store.NodeControlRPCComplete, store.NodeControlRPCProcessing, store.NodeControlRPCUncertain}
	for i, state := range states {
		id := "synthetic_recovery_" + state
		input := store.NodeControlRPCInput{CredentialDigest: f.digest, NodeID: f.binding.NodeID, BindingID: f.binding.OwnerBindingID, BindingVersion: f.binding.BindingVersion, NodeKeyID: f.binding.NodeKeyID, NodeKeyEpoch: f.binding.NodeKeyEpoch, Sequence: uint64(40 + i), OperationID: id, Operation: "node.binding.status", RequestDigest: nodewire.RecoveryDigest([]byte(id))}
		if _, _, err := f.c.store.BeginNodeControlRPC(input); err != nil {
			t.Fatal(err)
		}
		switch state {
		case store.NodeControlRPCComplete:
			if err := f.c.store.CompleteNodeControlRPC(store.NodeControlRPCCompletion{NodeControlRPCInput: input, ResponsePacket: []byte("SYNTHETIC PRIVATE RESPONSE MUST STAY IN INBOX")}); err != nil {
				t.Fatal(err)
			}
		case store.NodeControlRPCUncertain:
			if err := f.c.store.MarkNodeControlRPCUncertain(input); err != nil {
				t.Fatal(err)
			}
		}
		q.Operations = append(q.Operations, nodewire.RecoveryOperationQuery{OperationID: id, Sequence: input.Sequence, RequestDigest: input.RequestDigest})
	}
	q.Operations = append(q.Operations, nodewire.RecoveryOperationQuery{OperationID: "synthetic_absent", Sequence: 1, RequestDigest: nodewire.RecoveryDigest([]byte("synthetic_absent"))})
	packet := nodeTLSRecoverySeal(t, f, q)
	before := nodeTLSRecoveryEvidence(t, db)
	for attempt := 0; attempt < 2; attempt++ {
		reply, err := ReadNodeTLSRecoveryPacket(f.c.store, f.hub, f.digest, f.binding.NodeID, packet)
		if err != nil || len(reply) == 0 || len(reply) > nodewire.MaxRecoveryPacketBytes {
			t.Fatal("actual current recovery proof unavailable", err)
		}
		status, err := nodewire.OpenRecoveryResponse(f.node, nodeControlWireBinding(f.binding), q, packet, reply)
		if err != nil || status.AcceptedHighwater != 42 || len(status.Operations) != 4 {
			t.Fatal("sealed readonly snapshot lost exact highwater or scope", err)
		}
		for i, expected := range append(states, "NOT_RECORDED") {
			if status.Operations[i].State != expected {
				t.Fatal("recovery changed or guessed an operation state")
			}
		}
		encoded, err := json.Marshal(status)
		if err != nil || bytes.Contains(encoded, []byte("SYNTHETIC PRIVATE RESPONSE")) || bytes.Contains(encoded, []byte("response_packet")) {
			t.Fatal("status disclosed an operation body")
		}
	}
	if after := nodeTLSRecoveryEvidence(t, db); after != before {
		t.Fatal("recovery query mutated authorization, admission or permanent TLS evidence")
	}
	stale := store.NodeControlRPCInput{CredentialDigest: f.digest, NodeID: f.binding.NodeID, BindingID: f.binding.OwnerBindingID, BindingVersion: f.binding.BindingVersion, NodeKeyID: f.binding.NodeKeyID, NodeKeyEpoch: f.binding.NodeKeyEpoch, Sequence: 1, OperationID: "synthetic_stale_after_query", Operation: "node.binding.status", RequestDigest: nodewire.RecoveryDigest([]byte("stale"))}
	if _, _, err := f.c.store.BeginNodeControlRPC(stale); !errors.Is(err, store.ErrNodeControlRPCConflict) {
		t.Fatal("readonly recovery lowered normal admission highwater", err)
	}
	t.Run("wrong_operation_digest", func(t *testing.T) {
		wrong := q
		wrong.Operations = append([]nodewire.RecoveryOperationQuery(nil), q.Operations...)
		wrong.Operations[0].RequestDigest = nodewire.RecoveryDigest([]byte("synthetic changed operation content"))
		before := nodeTLSRecoveryEvidence(t, db)
		if reply, err := ReadNodeTLSRecoveryPacket(f.c.store, f.hub, f.digest, f.binding.NodeID, nodeTLSRecoverySeal(t, f, wrong)); len(reply) != 0 || !errors.Is(err, store.ErrNodeControlRPCConflict) || nodeTLSRecoveryEvidence(t, db) != before {
			t.Fatal("changed operation digest escaped exact readonly lookup", err)
		}
	})
	t.Run("maximum_operations", func(t *testing.T) {
		bounded := nodeTLSRecoveryQuery(f, active.Claims.ApplicationOrigin)
		for i := 0; i < nodewire.MaxRecoveryOperations; i++ {
			id := "synthetic_bound_" + hex.EncodeToString([]byte{byte(i)})
			bounded.Operations = append(bounded.Operations, nodewire.RecoveryOperationQuery{OperationID: id, Sequence: uint64(i + 1), RequestDigest: nodewire.RecoveryDigest([]byte(id))})
		}
		wire := nodeTLSRecoverySeal(t, f, bounded)
		before := nodeTLSRecoveryEvidence(t, db)
		reply, err := ReadNodeTLSRecoveryPacket(f.c.store, f.hub, f.digest, f.binding.NodeID, wire)
		if err != nil || len(reply) > nodewire.MaxRecoveryPacketBytes {
			t.Fatal("bounded recovery failed", err)
		}
		status, err := nodewire.OpenRecoveryResponse(f.node, nodeControlWireBinding(f.binding), bounded, wire, reply)
		if err != nil || len(status.Operations) != nodewire.MaxRecoveryOperations || nodeTLSRecoveryEvidence(t, db) != before {
			t.Fatal("bounded query lost state or changed durable evidence", err)
		}
	})
}

func TestNodeTLSRecoveryPacketNativeBindingDomainAndFreshReply(t *testing.T) {
	if !nodeTLSRecoveryNative(t) {
		return
	}
	f, active := nodeTLSRecoveryActive(t)
	q := nodeTLSRecoveryQuery(f, active.Claims.ApplicationOrigin)
	packet := nodeTLSRecoverySeal(t, f, q)
	for _, test := range []struct {
		name       string
		hub        *e2ee.Identity
		credential string
		nodeID     string
		wire       []byte
	}{
		{name: "foreign_actual_hub_public", hub: controlTLSActivationIdentity(t), credential: f.digest, nodeID: f.binding.NodeID, wire: packet},
		{name: "foreign_node_scope", hub: f.hub, credential: f.digest, nodeID: "synthetic_foreign_node", wire: packet},
		{name: "foreign_credential", hub: f.hub, credential: fabric.HashSessionCredential("SYNTHETIC FOREIGN RECOVERY TOKEN ONLY"), nodeID: f.binding.NodeID, wire: packet},
	} {
		t.Run(test.name, func(t *testing.T) {
			if reply, err := ReadNodeTLSRecoveryPacket(f.c.store, test.hub, test.credential, test.nodeID, test.wire); len(reply) != 0 || err == nil {
				t.Fatal("foreign actual key or scope authorized recovery")
			}
		})
	}
	t.Run("logical_origin_not_pq_origin", func(t *testing.T) {
		wrong := q
		wrong.Origin = active.Claims.HubPQOrigin
		if reply, err := ReadNodeTLSRecoveryPacket(f.c.store, f.hub, f.digest, f.binding.NodeID, nodeTLSRecoverySeal(t, f, wrong)); len(reply) != 0 || err == nil {
			t.Fatal("different Owner-approved origin namespace authorized query")
		}
	})
	t.Run("authenticated_wrong_credential", func(t *testing.T) {
		wrong := q
		wrong.CredentialDigest = fabric.HashSessionCredential("SYNTHETIC FOREIGN RECOVERY TOKEN ONLY")
		if reply, err := ReadNodeTLSRecoveryPacket(f.c.store, f.hub, f.digest, f.binding.NodeID, nodeTLSRecoverySeal(t, f, wrong)); len(reply) != 0 || err == nil {
			t.Fatal("authenticated request changed the current credential digest")
		}
	})
	t.Run("wrong_epoch", func(t *testing.T) {
		b := nodeControlWireBinding(f.binding)
		b.NodeKeyEpoch++
		wire, err := nodewire.SealRecoveryRequest(f.node, b, q)
		if err != nil {
			t.Fatal(err)
		}
		if reply, err := ReadNodeTLSRecoveryPacket(f.c.store, f.hub, f.digest, f.binding.NodeID, wire); len(reply) != 0 || err == nil {
			t.Fatal("foreign application key epoch accepted")
		}
	})
	t.Run("ordinary_rpc_domain", func(t *testing.T) {
		decoded, err := nodewire.DecodePacket(packet)
		if err != nil {
			t.Fatal(err)
		}
		body, err := json.Marshal(q)
		if err != nil {
			t.Fatal(err)
		}
		wire, err := nodewire.SealRequest(f.node, f.hub.Public(), nodeControlWireBinding(f.binding), decoded.Route, body)
		if err != nil {
			t.Fatal(err)
		}
		if reply, err := ReadNodeTLSRecoveryPacket(f.c.store, f.hub, f.digest, f.binding.NodeID, wire); len(reply) != 0 || err == nil {
			t.Fatal("ordinary RPC ciphertext crossed the recovery domain")
		}
	})
	reply, err := ReadNodeTLSRecoveryPacket(f.c.store, f.hub, f.digest, f.binding.NodeID, packet)
	if err != nil {
		t.Fatal(err)
	}
	t.Run("different_nonce", func(t *testing.T) {
		fresh := q
		fresh.Nonce = bytes.Repeat([]byte{0x75}, 32)
		if _, err := nodewire.OpenRecoveryResponse(f.node, nodeControlWireBinding(f.binding), fresh, packet, reply); err == nil {
			t.Fatal("cached reply authorized a fresh nonce")
		}
	})
	t.Run("different_packet_digest", func(t *testing.T) {
		freshWire := nodeTLSRecoverySeal(t, f, q)
		if bytes.Equal(freshWire, packet) {
			t.Fatal("synthetic sealing did not make independent ciphertext")
		}
		if _, err := nodewire.OpenRecoveryResponse(f.node, nodeControlWireBinding(f.binding), q, freshWire, reply); err == nil {
			t.Fatal("cached reply authorized a different ciphertext digest")
		}
	})
}

func TestNodeTLSRecoveryPacketNativeCurrentAuthorityDenials(t *testing.T) {
	if !nodeTLSRecoveryNative(t) {
		return
	}
	for _, kind := range []string{"owner_key_revoked", "owner_device_revoked", "owner_binding_revoked", "credential_revoked", "node_control_revoked", "node_control_epoch_changed", "tls_grant_revoked", "grant_signature_invalid", "leaf_invalid", "permanent_nonce_missing"} {
		t.Run(kind, func(t *testing.T) {
			f, active := nodeTLSRecoveryActive(t)
			db := nodeTLSRecoverySQL(t, f)
			q := nodeTLSRecoveryQuery(f, active.Claims.ApplicationOrigin)
			packet := nodeTLSRecoverySeal(t, f, q)
			switch kind {
			case "owner_key_revoked":
				if _, err := f.c.store.RevokeOwnerApprovalKeyLocal(f.binding.OwnerID, f.binding.OwnerKeyID, int64(active.Claims.OwnerKeyVersion)); err != nil {
					t.Fatal(err)
				}
			case "owner_device_revoked":
				if _, err := f.c.store.RevokeClientDevice(f.binding.OwnerID, f.binding.ClientDeviceID, f.device.Version); err != nil {
					t.Fatal(err)
				}
			case "owner_binding_revoked":
				if _, err := f.c.store.RevokeNodeDeviceBinding(f.binding.OwnerID, f.binding.OwnerBindingID, int64(f.binding.BindingVersion)); err != nil {
					t.Fatal(err)
				}
			case "credential_revoked":
				nodeTLSRecoveryExec(t, db, `UPDATE fabric_node_credentials SET status='revoked' WHERE node_id=?`, f.binding.NodeID)
			case "node_control_revoked":
				nodeTLSRecoveryExec(t, db, `UPDATE node_control_key_bindings_v1 SET state='REVOKED' WHERE owner_binding_id=?`, f.binding.OwnerBindingID)
			case "node_control_epoch_changed":
				nodeTLSRecoveryExec(t, db, `DROP TRIGGER node_control_key_binding_immutable_v1`)
				nodeTLSRecoveryExec(t, db, `UPDATE node_control_key_bindings_v1 SET node_key_epoch=node_key_epoch+1 WHERE owner_binding_id=?`, f.binding.OwnerBindingID)
			case "tls_grant_revoked":
				if err := f.c.store.RevokeNodeTLSGrantLocal(active.Claims.RequestID, active.RowVersion); err != nil {
					t.Fatal(err)
				}
			case "grant_signature_invalid", "leaf_invalid":
				// Remove immutability only in this disposable corruption fixture.
				nodeTLSRecoveryExec(t, db, `DROP TRIGGER node_tls_authority_v1_evidence_immutable`)
				if kind == "grant_signature_invalid" {
					nodeTLSRecoveryExec(t, db, `UPDATE node_tls_authority_v1 SET grant=? WHERE request_id=?`, []byte("SYNTHETIC INVALID OWNER SIGNATURE"), active.Claims.RequestID)
				} else {
					nodeTLSRecoveryExec(t, db, `UPDATE node_tls_authority_v1 SET leaf_pem=? WHERE request_id=?`, []byte("SYNTHETIC INVALID CERTIFICATE"), active.Claims.RequestID)
				}
			case "permanent_nonce_missing":
				nodeTLSRecoveryExec(t, db, `DROP TRIGGER node_tls_proof_nonces_v1_no_delete`)
				nodeTLSRecoveryExec(t, db, `DELETE FROM node_tls_proof_nonces_v1 WHERE request_id=? AND purpose='ACTIVATION'`, active.Claims.RequestID)
			}
			if kind == "grant_signature_invalid" || kind == "leaf_invalid" || kind == "permanent_nonce_missing" {
				current, err := f.c.store.ReadNodeTLSAuthorityRecoveryLocal(store.NodeTLSAuthorityStatusInput{NodeID: f.binding.NodeID, CredentialDigest: f.digest})
				if err != nil || current == nil || current.CurrentActiveState != store.NodeTLSAuthorityCurrentUnavailable || current.CurrentActive != nil {
					t.Fatal("unverifiable native ACTIVE was classified current", err)
				}
			}
			before := nodeTLSRecoveryEvidence(t, db)
			if reply, err := ReadNodeTLSRecoveryPacket(f.c.store, f.hub, f.digest, f.binding.NodeID, packet); len(reply) != 0 || err == nil {
				t.Fatal("stale, revoked or unverifiable current authority disclosed a recovery reply")
			}
			if nodeTLSRecoveryEvidence(t, db) != before {
				t.Fatal("rejected query changed persisted state")
			}
		})
	}
}

func TestNodeTLSRecoveryPacketNativeChangeBetweenRealReads(t *testing.T) {
	if !nodeTLSRecoveryNative(t) {
		return
	}
	for _, phase := range []string{"binding_after_first_read", "device_before_second_read", "tls_before_second_read"} {
		t.Run(phase, func(t *testing.T) {
			f, active := nodeTLSRecoveryActive(t)
			q := nodeTLSRecoveryQuery(f, active.Claims.ApplicationOrigin)
			packet := nodeTLSRecoverySeal(t, f, q)
			calls := 0
			readCurrent := func(input store.NodeTLSAuthorityStatusInput) (*store.NodeTLSAuthorityRecoveryStatus, error) {
				calls++
				if calls == 2 {
					if phase == "device_before_second_read" {
						if _, err := f.c.store.RevokeClientDevice(f.binding.OwnerID, f.binding.ClientDeviceID, f.device.Version); err != nil {
							t.Fatal(err)
						}
					} else if phase == "tls_before_second_read" {
						if err := f.c.store.RevokeNodeTLSGrantLocal(active.Claims.RequestID, active.RowVersion); err != nil {
							t.Fatal(err)
						}
					}
				}
				status, err := f.c.store.ReadNodeTLSAuthorityRecoveryLocal(input)
				if calls == 1 && phase == "binding_after_first_read" {
					if _, err := f.c.store.RevokeNodeDeviceBinding(f.binding.OwnerID, f.binding.OwnerBindingID, int64(f.binding.BindingVersion)); err != nil {
						t.Fatal(err)
					}
				}
				return status, err
			}
			if reply, err := readNodeTLSRecoveryPacket(f.c.store, f.hub, f.digest, f.binding.NodeID, packet, readCurrent); len(reply) != 0 || err == nil {
				t.Fatal("committed authority change between real reads released stale metadata")
			}
			if phase != "binding_after_first_read" && calls != 2 {
				t.Fatal("negative fixture did not reach the independent second read")
			}
		})
	}
}

func TestNodeTLSRecoveryPacketNativeHigherPendingAndBurnedFloor(t *testing.T) {
	if !nodeTLSRecoveryNative(t) {
		return
	}
	f, active := nodeTLSRecoveryActive(t)
	p, err := store.NodeTLSLeafParameters(active.Claims)
	if err != nil {
		t.Fatal(err)
	}
	leaf, err := pqtls.InspectTLSLeaf(active.LeafCertificatePEM, active.IssuerChainPEM, active.TrustAnchorPEM, p, time.Now().UTC().Truncate(time.Second))
	if err != nil {
		t.Fatal(err)
	}
	issuerSPKI, err := pqtls.TLSIssuerSigningSPKIHash(active.IssuerChainPEM)
	if err != nil {
		t.Fatal(err)
	}
	key, csr, err := pqtls.GenerateTLSCSR(p.TLSCSRParameters)
	if err != nil {
		t.Fatal(err)
	}
	defer key.Destroy()
	at := time.Now().UTC().Truncate(time.Second)
	// Public expectations come from the actual C-verified current certificate,
	// with a conservative validity interval. Reserve independently checks its
	// real issuer SPKI/DER namespace and this fresh CSR; no leaf is issued here.
	profile := pqtls.TLSIssuerProfile{Role: "node", CertificateDERHash: leaf.IssuerCertificateHash, SPKIDERHash: issuerSPKI, TrustAnchorDERHash: leaf.TrustAnchorDERHash, VerifiedNotBefore: leaf.VerifiedNotBefore, VerifiedNotAfter: leaf.VerifiedNotAfter}
	reserved, err := f.c.store.ReserveNodeTLSCandidate(store.NodeTLSCandidateInput{RequestID: "synthetic_recovery_pending_rotation", NodeID: f.binding.NodeID, CredentialDigest: f.digest, ExpectedTLSEpochFloor: active.Claims.TLSEpoch, CSRPEM: csr.CSRPEM, IssuerChainPEM: active.IssuerChainPEM, TrustAnchorPEM: active.TrustAnchorPEM, Parameters: csr.Parameters, Issuer: profile, IssuerGeneration: active.Claims.IssuerGeneration, NotBefore: at, NotAfter: p.NotAfter, HubSPKIHash: active.Claims.HubSPKIHash, HubTrustAnchorDERHash: active.Claims.HubTrustAnchorDERHash, HubPQOrigin: active.Claims.HubPQOrigin, ApplicationOrigin: active.Claims.ApplicationOrigin, GrantIssuedAt: at, GrantExpiresAt: p.NotAfter, GrantNonce: e2ee.NodeTLSAuthorityDigest([]byte("SYNTHETIC RECOVERY ROTATION GRANT ONLY"))})
	if err != nil {
		t.Fatal("reserve actual fresh CSR without changing current ACTIVE", err)
	}
	q := nodeTLSRecoveryQuery(f, active.Claims.ApplicationOrigin)
	packet := nodeTLSRecoverySeal(t, f, q)
	check := func(t *testing.T, wantPending int) {
		t.Helper()
		current, err := f.c.store.ReadNodeTLSAuthorityRecoveryLocal(store.NodeTLSAuthorityStatusInput{NodeID: f.binding.NodeID, CredentialDigest: f.digest})
		if err != nil || current.CurrentActiveState != store.NodeTLSAuthorityCurrentVerified || !reflect.DeepEqual(current.CurrentActive, active) || current.BurnedTLSEpochFloor != reserved.Claims.TLSEpoch || len(current.Pending) != wantPending {
			t.Fatal("higher reservation/burn displaced exact previous ACTIVE", err)
		}
		reply, err := ReadNodeTLSRecoveryPacket(f.c.store, f.hub, f.digest, f.binding.NodeID, packet)
		if err != nil {
			t.Fatal("valid previous ACTIVE could not query recovery", err)
		}
		if _, err := nodewire.OpenRecoveryResponse(f.node, nodeControlWireBinding(f.binding), q, packet, reply); err != nil {
			t.Fatal(err)
		}
	}
	t.Run("higher_pending_keeps_active", func(t *testing.T) { check(t, 1) })
	grant, err := e2ee.SignOwnerTLSLeafGrant(f.owner, reserved.Claims)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.c.store.BeginNodeTLSLeafIssue(store.NodeTLSLeafIssueInput{NodeTLSAuthorityActionInput: store.NodeTLSAuthorityActionInput{RequestID: reserved.Claims.RequestID, NodeID: f.binding.NodeID, CredentialDigest: f.digest, ExpectedVersion: reserved.RowVersion}, Grant: grant}); err != nil {
		t.Fatal(err)
	}
	if err := f.c.store.MarkNodeTLSLeafUncertainLocal(reserved.Claims.RequestID); err != nil {
		t.Fatal(err)
	}
	t.Run("burned_uncertain_keeps_active", func(t *testing.T) { check(t, 0) })
}
