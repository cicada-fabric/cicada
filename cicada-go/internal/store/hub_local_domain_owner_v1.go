package store

import (
	"database/sql"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"reflect"
	"time"

	"github.com/cicada-ai/cicada/internal/e2ee"
	wire "github.com/cicada-ai/cicada/internal/hubaccountwire"
)

const localDomainReadLifetime = 5 * time.Minute

func localDomainFresh(c wire.AppNodeRequestContext, at time.Time) bool {
	i, err := time.Parse(time.RFC3339Nano, c.IssuedAt)
	return err == nil && !i.After(at.Add(30*time.Second)) && !i.Before(at.Add(-time.Minute))
}

func localDomainRateTx(tx *sql.Tx, kind, id string, epoch uint64, at time.Time) error {
	var stamp string
	var count int
	err := tx.QueryRow(`SELECT window_start,requests FROM hub_local_domain_rates_v1 WHERE actor_kind=? AND actor_id=? AND epoch=?`, kind, id, epoch).Scan(&stamp, &count)
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		return err
	}
	start, e := time.Parse(time.RFC3339Nano, stamp)
	if e != nil || !at.Before(start.Add(time.Minute)) {
		stamp = appNodeStamp(at)
		count = 0
	}
	if count >= 128 {
		return ErrHubOwnerDiagnosticsFull
	}
	_, err = tx.Exec(`INSERT INTO hub_local_domain_rates_v1 VALUES(?,?,?,?,?) ON CONFLICT(actor_kind,actor_id,epoch) DO UPDATE SET window_start=excluded.window_start,requests=excluded.requests`, kind, id, epoch, stamp, count+1)
	return err
}

func (s *Store) ProcessHubLocalDomain(in HubLocalDomainInput, seal HubLocalDomainSeal) ([]byte, error) {
	if seal == nil || s.requireOwnerSetupStartupAllowed() != nil {
		return nil, ErrHubAccountRejected
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	tx, err := s.db.Begin()
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()
	lock, err := tx.Exec(`UPDATE hub_local_domain_guard_v1 SET touched_at=touched_at WHERE id=1`)
	if err != nil {
		return nil, err
	}
	if n, e := lock.RowsAffected(); e != nil || n != 1 {
		return nil, ErrHubAccountRejected
	}
	if in.Now != nil {
		in.At = in.Now().UTC()
	}
	_, c, token, _, err := localDomainInput(in)
	if err != nil {
		return nil, err
	}
	a, err := appNodeActor(tx, in.Hub, c.DeviceID, in.Device, token, in.At)
	if err != nil || c.OwnerID != a.scope.OwnerID || c.AccountID != a.scope.AccountID || c.DeviceID != a.scope.DeviceID || c.Origin != a.scope.Origin {
		return nil, ErrHubAccountRejected
	}
	r, err := localDomainOwnerProcessTx(tx, a, in, seal, false)
	if err != nil {
		return nil, err
	}
	if err = tx.Commit(); err != nil {
		return nil, err
	}
	return r.packet, nil
}

func localDomainOwnerCachedTx(tx *sql.Tx, c wire.AppNodeRequestContext, op, digest string, at time.Time) (localDomainReceipt, error) {
	for _, table := range []string{"hub_local_domain_owner_operations_v1", "hub_local_domain_owner_reads_v1"} {
		var oldOp, oldDigest, created string
		var r localDomainReceipt
		err := tx.QueryRow(`SELECT operation,request_digest,state,response_packet,created_at FROM `+table+` WHERE owner_id=? AND device_id=? AND operation_id=?`, c.OwnerID, c.DeviceID, c.RequestID).Scan(&oldOp, &oldDigest, &r.state, &r.packet, &created)
		if errors.Is(err, sql.ErrNoRows) {
			continue
		}
		if err != nil {
			return r, err
		}
		if oldOp != op || oldDigest != digest {
			return localDomainReceipt{}, ErrHubAccountRejected
		}
		if table == "hub_local_domain_owner_operations_v1" {
			return r, nil
		}
		start, err := time.Parse(time.RFC3339Nano, created)
		if err != nil {
			return localDomainReceipt{}, ErrHubAccountRejected
		}
		if at.Before(start.Add(localDomainReadLifetime)) {
			return r, nil
		}
		return localDomainReceipt{}, nil
	}
	return localDomainReceipt{}, nil
}

func localDomainOwnerSaveTx(tx *sql.Tx, c wire.AppNodeRequestContext, op, policy, digest, nonce, state string, packet []byte, at time.Time) error {
	read := op == wire.OperationLocalDomainStatus || op == wire.OperationLocalDomainReconcile
	if !read {
		if len(packet) == 0 || len(packet) > wire.MaxLocalDomainPacketBytes {
			return ErrHubAccountRejected
		}
		_, err := tx.Exec(`INSERT INTO hub_local_domain_owner_operations_v1 VALUES(?,?,?,?,?,?,?,?,?,?)`, c.OwnerID, c.DeviceID, c.RequestID, op, policy, digest, nonce, state, packet, appNodeStamp(at))
		return err
	}
	if len(packet) == 0 || len(packet) > wire.MaxLocalDomainReconcilePacketBytes {
		return ErrHubAccountRejected
	}
	rows, err := tx.Query(`SELECT operation_id,created_at FROM hub_local_domain_owner_reads_v1 WHERE owner_id=? AND device_id=? ORDER BY rowid DESC`, c.OwnerID, c.DeviceID)
	if err != nil {
		return err
	}
	var drop []string
	live := 0
	for rows.Next() {
		var id, created string
		if err = rows.Scan(&id, &created); err != nil {
			break
		}
		start, e := time.Parse(time.RFC3339Nano, created)
		if e != nil {
			err = ErrHubAccountRejected
			break
		}
		if !at.Before(start.Add(localDomainReadLifetime)) || id == c.RequestID {
			drop = append(drop, id)
		} else {
			live++
		}
	}
	re := rows.Err()
	rows.Close()
	if err != nil {
		return err
	}
	if re != nil {
		return re
	}
	if live >= 128 {
		return ErrHubOwnerDiagnosticsFull
	}
	for _, id := range drop {
		if _, err = tx.Exec(`DELETE FROM hub_local_domain_owner_reads_v1 WHERE owner_id=? AND device_id=? AND operation_id=?`, c.OwnerID, c.DeviceID, id); err != nil {
			return err
		}
	}
	_, err = tx.Exec(`INSERT INTO hub_local_domain_owner_reads_v1 VALUES(?,?,?,?,?,?,?,?,?)`, c.OwnerID, c.DeviceID, c.RequestID, op, digest, nonce, state, packet, appNodeStamp(at))
	return err
}

func localDomainResult(in HubLocalDomainInput, c wire.AppNodeRequestContext, op, state, code string, policy *hubLocalDomain) wire.LocalDomainResult {
	r := wire.LocalDomainResult{Format: wire.LocalDomainFormat, Operation: op, RequestID: c.RequestID, RequestPacketDigest: wire.LocalDomainPacketDigest(in.Packet), HubID: c.HubID, OwnerID: c.OwnerID, DeviceID: c.DeviceID, State: state, NoEffect: state != wire.AppNodeCompleted, ErrorCode: code, ObservedAt: appNodeStamp(in.At)}
	if policy != nil {
		r.PolicyID = policy.policy.PolicyID
		r.PolicyEpoch = policy.policy.Epoch
	}
	return r
}

func localDomainOwnerProcessTx(tx *sql.Tx, a *hubAppNodeActor, in HubLocalDomainInput, seal HubLocalDomainSeal, fence bool) (localDomainReceipt, error) {
	op, c, _, raw, err := localDomainInput(in)
	if err != nil {
		return localDomainReceipt{}, err
	}
	digest := wire.LocalDomainPacketDigest(in.Packet)
	old, err := localDomainOwnerCachedTx(tx, c, op, digest, in.At)
	if err != nil || len(old.packet) > 0 {
		return old, err
	}
	if err = localDomainRateTx(tx, "OWNER", c.OwnerID+"/"+c.DeviceID, a.scope.DeviceEpoch, in.At); err != nil {
		return localDomainReceipt{}, err
	}
	if op == wire.OperationLocalDomainReconcile {
		return localDomainOwnerReconcileTx(tx, a, in, seal)
	}
	claims, err := e2ee.VerifyOwnerLocalDomainRequest(a.scope.OwnerPublic, raw, wire.LocalDomainOwnerPurpose(op), time.Time{})
	if err != nil || claims.Scope.OwnerID != a.scope.OwnerID || claims.Scope.DeviceID != a.scope.DeviceID || !reflect.DeepEqual(claims.Scope.DevicePublic, in.Device) {
		return localDomainReceipt{}, ErrHubAccountRejected
	}
	nonce := AccountDigest("local-domain-owner-nonce", c.ClientNonce)
	var used int
	if err = tx.QueryRow(`SELECT (SELECT count(*) FROM hub_local_domain_owner_operations_v1 WHERE owner_id=? AND device_id=? AND nonce_digest=?)+(SELECT count(*) FROM hub_local_domain_owner_reads_v1 WHERE owner_id=? AND device_id=? AND nonce_digest=? AND operation_id!=?)`, c.OwnerID, c.DeviceID, nonce, c.OwnerID, c.DeviceID, nonce, c.RequestID).Scan(&used); err != nil {
		return localDomainReceipt{}, err
	}
	code := ""
	if used != 0 {
		code = "REPLAY_CONFLICT"
		nonce = ""
	} else if fence {
		code = "REJECTED_UNADMITTED"
	} else if !localDomainFresh(c, in.At) || e2ee.ValidateOwnerLocalDomainRequest(claims, in.At) != nil {
		code = "PROOF_EXPIRED"
	} else if !appNodeScopeCurrent(a, claims.Scope) {
		code = "AUTHORITY_UNAVAILABLE"
	}
	if op == wire.OperationLocalDomainStatus {
		issued, e := time.Parse(time.RFC3339Nano, c.IssuedAt)
		if e != nil || issued.After(in.At.Add(30*time.Second)) {
			return localDomainReceipt{}, ErrHubAccountRejected
		}
		if code != "" {
			return localDomainOwnerFenceTx(tx, in, c, op, nonce, "READ_EXPIRED", wire.AppNodeReadExpired, seal)
		}
		return localDomainOwnerStatusTx(tx, in, c, claims, nonce, seal)
	}
	if code != "" {
		return localDomainOwnerFenceTx(tx, in, c, op, nonce, code, wire.AppNodeRejectedFenced, seal)
	}
	if _, err = tx.Exec(`SAVEPOINT local_domain_owner_effect`); err != nil {
		return localDomainReceipt{}, err
	}
	var body any
	var policy string
	switch op {
	case wire.OperationLocalDomainPrepare:
		body, policy, err = localDomainOwnerPrepareTx(tx, a, in, claims)
	case wire.OperationLocalDomainActivate:
		body, policy, err = localDomainOwnerActivateTx(tx, a, in, c, claims)
	case wire.OperationLocalDomainRevoke:
		body, policy, err = localDomainOwnerRevokeTx(tx, a, in, c, claims)
	default:
		err = ErrHubAccountRejected
	}
	if err != nil {
		if _, e := tx.Exec(`ROLLBACK TO local_domain_owner_effect`); e != nil {
			return localDomainReceipt{}, e
		}
		if _, e := tx.Exec(`RELEASE local_domain_owner_effect`); e != nil {
			return localDomainReceipt{}, e
		}
		return localDomainOwnerFenceTx(tx, in, c, op, nonce, "LOCAL_DOMAIN_REJECTED", wire.AppNodeRejectedFenced, seal)
	}
	if _, err = tx.Exec(`RELEASE local_domain_owner_effect`); err != nil {
		return localDomainReceipt{}, err
	}
	packet, err := seal(body)
	if err != nil {
		return localDomainReceipt{}, err
	}
	if err = localDomainOwnerSaveTx(tx, c, op, policy, digest, nonce, wire.AppNodeCompleted, packet, in.At); err != nil {
		return localDomainReceipt{}, err
	}
	return localDomainReceipt{packet: packet, state: wire.AppNodeCompleted, policy: policy}, nil
}

func localDomainOwnerFenceTx(tx *sql.Tx, in HubLocalDomainInput, c wire.AppNodeRequestContext, op, nonce, code, state string, seal HubLocalDomainSeal) (localDomainReceipt, error) {
	r := localDomainResult(in, c, op, state, code, nil)
	if op != wire.OperationLocalDomainPrepare {
		var p e2ee.OwnerLocalDomainRequestProof
		_, _, _, raw, _ := localDomainOwnerFields(in.Body)
		if json.Unmarshal(raw, &p) != nil {
			return localDomainReceipt{}, ErrHubAccountRejected
		}
		r.PolicyID = p.Claims.PolicyID
		r.PolicyEpoch = p.Claims.PolicyEpoch
	}
	packet, err := seal(r)
	if err != nil {
		return localDomainReceipt{}, err
	}
	if err = localDomainOwnerSaveTx(tx, c, op, r.PolicyID, wire.LocalDomainPacketDigest(in.Packet), nonce, state, packet, in.At); err != nil {
		return localDomainReceipt{}, err
	}
	return localDomainReceipt{packet: packet, state: state, policy: r.PolicyID}, nil
}

func localDomainOwnerPrepareTx(tx *sql.Tx, a *hubAppNodeActor, in HubLocalDomainInput, c e2ee.OwnerLocalDomainRequestClaims) (any, string, error) {
	if c.Target == nil {
		return nil, "", ErrHubAccountRejected
	}
	target := *c.Target
	b, err := localDomainNodeBindingTx(tx, target.Node.NodeID, "", 0, true)
	if err != nil || b.OwnerID != a.scope.OwnerID || !reflect.DeepEqual(b.HubPublicIdentity, in.NodeControlPublic) {
		return nil, "", ErrHubAccountRejected
	}
	current, expected := appNodeBindingPublic(*b), target.Node
	current.NodeName, expected.NodeName = "", ""
	if !reflect.DeepEqual(current, expected) {
		return nil, "", ErrHubAccountRejected
	}
	var report []byte
	if tx.QueryRow(`SELECT report FROM hub_local_domain_user_reports_v1 WHERE owner_binding_id=? AND node_key_epoch=?`, b.OwnerBindingID, b.NodeKeyEpoch).Scan(&report) != nil {
		return nil, "", ErrHubAccountRejected
	}
	r, err := e2ee.VerifyLocalDomainUserReport(target.Node, report, in.At)
	if err != nil || (target.LocalUserScope != "" && target.LocalUserScope != r.LocalUserScope) {
		return nil, "", ErrHubAccountRejected
	}
	issued, _ := time.Parse(time.RFC3339Nano, r.IssuedAt)
	if issued.After(in.At) {
		return nil, "", ErrHubAccountRejected
	}
	rows, err := tx.Query(`SELECT policy_id FROM hub_local_domains_v1 WHERE owner_id=? AND node_id=? AND local_user_scope=? AND state IN('PREPARED','ACTIVE')`, a.scope.OwnerID, target.Node.NodeID, r.LocalUserScope)
	if err != nil {
		return nil, "", err
	}
	var ids []string
	for rows.Next() {
		var id string
		if err = rows.Scan(&id); err != nil {
			break
		}
		ids = append(ids, id)
	}
	re := rows.Err()
	rows.Close()
	if err != nil {
		return nil, "", err
	}
	if re != nil {
		return nil, "", re
	}
	for _, id := range ids {
		p, e := readLocalDomain(tx, id)
		if e != nil {
			return nil, "", e
		}
		if e = localDomainExpireTx(tx, p, in.At); e != nil {
			return nil, "", e
		}
		if p.state == wire.LocalDomainPrepared || p.state == wire.LocalDomainActive {
			return nil, "", ErrHubAccountRejected
		}
	}
	network, name := target.NetworkID, target.NewNetworkName
	if network == "" {
		network = NewID("net")
	} else {
		if tx.QueryRow(`SELECT name FROM networks_v2 WHERE id=? AND hub_id=? AND owner_id=? AND state='ACTIVE'`, network, in.Hub.HubID, a.scope.OwnerID).Scan(&name) != nil {
			return nil, "", ErrHubAccountRejected
		}
	}
	var epoch uint64
	err = tx.QueryRow(`SELECT epoch FROM hub_local_domain_epochs_v1 WHERE owner_id=? AND node_id=? AND local_user_scope=?`, a.scope.OwnerID, b.NodeID, r.LocalUserScope).Scan(&epoch)
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		return nil, "", err
	}
	if epoch >= 1<<63-2 {
		return nil, "", ErrHubAccountRejected
	}
	epoch++
	if _, err = tx.Exec(`INSERT INTO hub_local_domain_epochs_v1 VALUES(?,?,?,?) ON CONFLICT(owner_id,node_id,local_user_scope) DO UPDATE SET epoch=excluded.epoch`, a.scope.OwnerID, b.NodeID, r.LocalUserScope, epoch); err != nil {
		return nil, "", err
	}
	id, err := wire.NewRequestID()
	if err != nil {
		return nil, "", err
	}
	nonce, err := wire.NewNonce()
	if err != nil {
		return nil, "", err
	}
	credential, err := base64.RawURLEncoding.DecodeString(b.CredentialDigest)
	if err != nil || len(credential) != 32 {
		return nil, "", ErrHubAccountRejected
	}
	policy := e2ee.LocalDomainPolicy{Version: 1, PolicyID: id, Epoch: epoch, Origin: a.scope.Origin, HubID: in.Hub.HubID, HubFingerprint: a.scope.HubFingerprint, OwnerID: a.scope.OwnerID, OwnerPublic: a.scope.OwnerPublic, OwnerKeyVersion: a.scope.OwnerKeyVersion, Node: target.Node, NodeControlBindingVersion: b.Version, CredentialCommitment: hex.EncodeToString(credential), LocalUserScope: r.LocalUserScope, NetworkID: network, NetworkName: name, CreateNetwork: target.NetworkID == "", GroupID: NewID("grp"), GroupName: target.GroupName, Rights: e2ee.LocalDomainRights(), IssuedAt: appNodeStamp(in.At), ExpiresAt: target.ExpiresAt, PrepareRequestID: c.RequestID, PreparePacketDigest: wire.LocalDomainPacketDigest(in.Packet), ServerNonce: hex.EncodeToString(nonce)}
	if wire.ValidateLocalDomainPolicy(policy, in.Hub, in.At) != nil {
		return nil, "", ErrHubAccountRejected
	}
	end := in.At.Add(e2ee.LocalDomainRequestLifetime)
	for _, stamp := range []string{c.ExpiresAt, c.Scope.AccountSessionExpiresAt, r.ExpiresAt} {
		t, e := time.Parse(time.RFC3339Nano, stamp)
		if e != nil {
			return nil, "", ErrHubAccountRejected
		}
		if t.Before(end) {
			end = t
		}
	}
	raw, err := json.Marshal(policy)
	if err != nil {
		return nil, "", err
	}
	_, _, _, prepareProof, _ := localDomainOwnerFields(in.Body)
	hubJSON, err := json.Marshal(in.Hub)
	if err != nil {
		return nil, "", err
	}
	_, err = tx.Exec(`INSERT INTO hub_local_domains_v1(policy_id,hub_id,owner_id,node_id,local_user_scope,network_id,group_id,epoch,policy_json,hub_identity_json,state,revision,creator_account_id,creator_device_id,prepare_proof,user_report,proof_expires_at,created_at) VALUES(?,?,?,?,?,?,?,?,?,?,'PREPARED',1,?,?,?,?,?,?)`, id, policy.HubID, policy.OwnerID, b.NodeID, policy.LocalUserScope, network, policy.GroupID, epoch, string(raw), string(hubJSON), a.scope.AccountID, a.scope.DeviceID, prepareProof, report, appNodeStamp(end), policy.IssuedAt)
	if err != nil {
		return nil, "", err
	}
	return wire.LocalDomainChallenge{Format: wire.LocalDomainFormat, RequestID: c.RequestID, RequestPacketDigest: policy.PreparePacketDigest, PrepareProofDigest: wire.LocalDomainProofDigest(prepareProof), LocalUserReport: report, Policy: policy, Revision: 1, ProofExpiresAt: appNodeStamp(end), ObservedAt: policy.IssuedAt}, id, nil
}
