package hubauth

import (
	"context"
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"errors"
	"reflect"
	"time"

	"github.com/cicada-ai/cicada/internal/e2ee"
	wire "github.com/cicada-ai/cicada/internal/hubaccountwire"
	"github.com/cicada-ai/cicada/internal/ownerbootstrap"
	"github.com/cicada-ai/cicada/internal/store"
)

// IssueActivationLocal is a trusted installation-channel operation. Neither a
// public account session nor Control can issue or replace this authority.
func (s *Service) IssueActivationLocal(purpose, keyID, fingerprint string, cancel bool) (*wire.ActivationMaterial, error) {
	setup, epoch, owner, err := s.db.HubActivationIssueScopeLocal(purpose, keyID, fingerprint)
	if err != nil {
		return nil, err
	}
	hub, err := s.HubIdentity()
	if err != nil {
		return nil, err
	}
	fp, err := wire.HubFingerprint(hub)
	if err != nil {
		return nil, err
	}
	id, err := wire.NewRequestID()
	if err != nil {
		return nil, err
	}
	secret, err := wire.NewNonce()
	if err != nil {
		return nil, err
	}
	defer clear(secret)
	at := s.requestTime()
	m := wire.ActivationMaterial{Format: wire.ActivationFormat, Version: 1, Purpose: purpose, Origin: setup.Origin, AllowLoopbackHTTP: setup.AllowLoopbackHTTP, HubID: setup.HubID, HubFingerprint: fp, AccountID: setup.AccountID, OwnerID: setup.OwnerID, ActivationID: id, SetupEpoch: uint64(setup.Version), AccountEpoch: uint64(epoch), ExpectedOwnerPublic: owner, Code: base64.RawURLEncoding.EncodeToString(secret), IssuedAt: stamp(at), ExpiresAt: stamp(at.Add(wire.MaxActivationLifetime))}
	if err = s.db.IssueHubActivationLocal(m, activationCodeDigest(m), cancel); err != nil {
		return nil, err
	}
	return &m, nil
}
func activationCodeDigest(m wire.ActivationMaterial) string {
	raw, _ := json.Marshal(m)
	defer clear(raw)
	return store.AccountDigest("activation-code", raw)
}
func redactedMaterial(m wire.ActivationMaterial) wire.ActivationMaterial { m.Code = ""; return m }

func (s *Service) activationResult(operation string, requestID, digest, activationID, deviceID, state string, setup *store.HubOwnerSetup, epoch int64) wire.ActivationResult {
	root := wire.RootPendingState
	if setup.RootEverEstablished {
		root = wire.RootUnavailableState
	}
	if setup.SignerState == "OWNER_SIGNER_READY" {
		root = wire.RootActiveState
	}
	r := wire.ActivationResult{Format: wire.ActivationResultFormat, Operation: operation, RequestID: requestID, RequestPacketDigest: digest, Origin: setup.Origin, HubID: setup.HubID, AccountID: setup.AccountID, OwnerID: setup.OwnerID, ActivationID: activationID, DeviceID: deviceID, AccountEpoch: uint64(epoch), DeviceEpoch: 1, State: state, RootState: root, LeaseState: wire.ActivationLeaseUnavailable, AllowedOperations: []string{}, LoginRequired: true, ObservedAt: stamp(s.requestTime())}
	if d, err := s.db.HubAccountDiagnosticDevice(setup.AccountID, deviceID); err == nil {
		r.DeviceEpoch = uint64(d.Epoch)
	}
	if l, err := s.db.HubAppLease(setup.OwnerID, deviceID); err == nil && l != nil {
		r.LeaseState = l.State
		r.LeaseExpiresAt = l.Binding.LeaseExpiresAt
		r.LoginRequired = l.LoginRequired
		if l.State == wire.ActivationLeaseActive {
			r.AllowedOperations = wire.ActivationAllowedOperations()
		}
	}
	return r
}
func (s *Service) handleExtension(ctx context.Context, operation string, raw []byte) (response []byte, err error) {
	p, err := wire.PreflightRequest(raw, operation)
	if err != nil {
		return nil, ErrAuthentication
	}
	setup, epoch, err := s.db.HubAccountSetup()
	if err != nil {
		return nil, ErrAuthentication
	}
	hub, err := s.HubIdentity()
	if err != nil {
		return nil, err
	}
	route := p.Packet.Route
	trusted := p.SenderPublicIdentity
	if route.HubID != setup.HubID || route.OwnerID != setup.OwnerID {
		return nil, ErrAuthentication
	}
	if operation == wire.OperationAccountReconcile {
		d, e := s.db.HubAccountDiagnosticDevice(setup.AccountID, route.DeviceID)
		if e != nil || !reflect.DeepEqual(d.Public, trusted) {
			return nil, ErrAuthentication
		}
	}
	binding, expected, err := wire.RequestRoute(hub, setup.OwnerID, route.DeviceID, route.OperationID, operation, wire.HandshakeEpoch, trusted)
	if err != nil || expected != route {
		return nil, ErrAuthentication
	}
	release, err := s.acquire(ctx)
	if err != nil {
		return nil, err
	}
	defer release()
	defer func() {
		if err != nil {
			if errors.Is(err, store.ErrHubOwnerDiagnosticsFull) {
				err = ErrBusy
			} else {
				err = ErrAuthentication
			}
		}
	}()
	digest := wire.ActivationPacketDigest(raw)
	prior, err := s.db.HubOwnerOperation(setup.AccountID, route.DeviceID, route.OperationID)
	if err != nil {
		return nil, err
	}
	if prior != nil && (prior.Operation != operation || prior.Digest != digest) {
		return nil, ErrAuthentication
	}
	open := func(out any) error {
		return wire.OpenRequestAt(s.ids.ClientControl, &trusted, binding, route, raw, out, time.Time{})
	}
	fresh := func(out any) bool {
		return wire.OpenRequestAt(s.ids.ClientControl, &trusted, binding, route, raw, out, s.requestTime()) == nil
	}
	seal := func(body any) ([]byte, error) { return wire.SealResponse(s.ids.ClientControl, trusted, route, body) }
	operationRecord := func(nonce []byte, state string, response []byte) store.HubOwnerOperation {
		return store.HubOwnerOperation{AccountID: setup.AccountID, OwnerID: setup.OwnerID, DeviceID: route.DeviceID, Operation: operation, ID: route.OperationID, Digest: digest, State: state, NonceDigest: nonceDigest(nonce), Epoch: epoch, Response: response}
	}
	replay := func(activationID string) ([]byte, error) {
		packet, e := s.db.ReplayHubActivationOperation(activationID, setup.AccountID, route.DeviceID, route.OperationID, digest)
		if e == nil {
			return packet, nil
		}
		current, ce, err := s.db.HubAccountSetup()
		if err != nil {
			return nil, err
		}
		result := s.activationResult(operation, route.OperationID, digest, activationID, route.DeviceID, wire.ActivationCancelled, current, ce)
		return seal(result)
	}
	reject := func(activationID string, nonce []byte) ([]byte, error) {
		r := s.activationResult(operation, route.OperationID, digest, activationID, route.DeviceID, wire.ActivationRejected, setup, epoch)
		packet, e := seal(r)
		if e != nil {
			return nil, e
		}
		record := operationRecord(nonce, wire.ActivationRejected, packet)
		// A refused operation consumes no authority. Its durable ID/digest fence
		// must still be recordable when refusal was caused by a reused nonce.
		record.NonceDigest = ""
		if _, e = s.db.RejectHubOwnerOperation(record); e != nil {
			return nil, e
		}
		return replay(activationID)
	}
	switch operation {
	case wire.OperationActivationPrepare:
		var req wire.ActivationPrepare
		if err = open(&req); err != nil {
			return nil, err
		}
		a, e := s.db.HubActivation(req.Material.ActivationID)
		if e != nil {
			return nil, e
		}
		got := activationCodeDigest(req.Material)
		if subtle.ConstantTimeCompare([]byte(got), []byte(a.CodeDigest)) != 1 || !reflect.DeepEqual(redactedMaterial(req.Material), a.Material) {
			return nil, ErrAuthentication
		}
		if prior != nil {
			return replay(a.Material.ActivationID)
		}
		for _, key := range []*e2ee.Identity{s.ids.Peer, s.ids.ClientControl, s.ids.NodeControl} {
			if req.OwnerPublic.ID == key.Public().ID || trusted.ID == key.Public().ID {
				return reject(a.Material.ActivationID, req.ClientNonce)
			}
		}
		if !fresh(&wire.ActivationPrepare{}) || a.State != wire.ActivationIssued {
			return reject(a.Material.ActivationID, req.ClientNonce)
		}
		at := s.requestTime()
		grant, e := e2ee.VerifyOwnerDeviceGrant(req.OwnerDeviceGrant, req.OwnerPublic, trusted, setup.OwnerID, req.OwnerPublic.ID, route.DeviceID, setup.HubID, e2ee.OwnerDevicePurposeControl, at)
		if e != nil {
			return reject(a.Material.ActivationID, req.ClientNonce)
		}
		deviceEpoch := uint64(1)
		if d, e := s.db.HubAccountDiagnosticDevice(setup.AccountID, route.DeviceID); e == nil {
			if d.State != wire.DeviceActiveState || !reflect.DeepEqual(d.Public, trusted) {
				return reject(a.Material.ActivationID, req.ClientNonce)
			}
			deviceEpoch = uint64(d.Epoch)
		}
		b := wire.ActivationBinding{Format: wire.ActivationFormat, Purpose: a.Material.Purpose, Origin: setup.Origin, HubID: setup.HubID, HubFingerprint: a.Material.HubFingerprint, AccountID: setup.AccountID, OwnerID: setup.OwnerID, ActivationID: a.Material.ActivationID, SetupEpoch: uint64(setup.Version), AccountEpoch: uint64(epoch), DeviceEpoch: deviceEpoch, OwnerPublic: req.OwnerPublic, DeviceID: route.DeviceID, DevicePublic: trusted, PrepareRequestID: route.OperationID, PreparePacketDigest: digest, GrantDigest: wire.ActivationGrantDigest(req.OwnerDeviceGrant), AllowedOperations: wire.ActivationAllowedOperations(), LeaseExpiresAt: stamp(at.Add(wire.MaxAppLeaseLifetime))}
		expiry := at.Add(wire.MaxActivationProofLifetime)
		for _, text := range []string{a.Material.ExpiresAt, grant.ExpiresAt} {
			t, e := time.Parse(time.RFC3339Nano, text)
			if e != nil {
				return nil, e
			}
			if t.Before(expiry) {
				expiry = t
			}
		}
		pair := ownerbootstrap.PairingFile{Format: ownerbootstrap.Format, Origin: setup.Origin, AllowLoopbackHTTP: setup.AllowLoopbackHTTP, Hub: hub, Manifest: ownerbootstrap.Manifest{Version: 1, Purpose: ownerbootstrap.Purpose, AccountID: setup.AccountID, OwnerID: setup.OwnerID, HubID: setup.HubID, AuthorityID: a.Material.ActivationID, OperationID: b.Digest(), CandidatePublic: req.OwnerPublic, CandidateFingerprint: ownerbootstrap.Fingerprint(req.OwnerPublic), ExpiresAt: stamp(expiry)}}
		pair, ownerNonce, e := ownerbootstrap.CreateChallenge(s.ids.ClientControl, pair, at)
		if e != nil {
			return reject(a.Material.ActivationID, req.ClientNonce)
		}
		nonce, e := wire.NewNonce()
		if e != nil {
			return nil, e
		}
		defer clear(nonce)
		ch := wire.ActivationChallenge{Format: wire.ActivationChallengeFormat, Binding: b, ClientNonce: req.ClientNonce, ServerNonce: nonce, Proof: pair, IssuedAt: stamp(at), ExpiresAt: stamp(expiry)}
		packet, e := seal(ch)
		if e != nil {
			return nil, e
		}
		packet, e = s.db.PrepareHubActivation(store.HubActivationPreparation{ID: a.Material.ActivationID, Binding: b, Pairing: pair, Grant: req.OwnerDeviceGrant, Packet: packet, OwnerNonceDigest: ownerNonce, DeviceNonceDigest: nonceDigest(nonce), PrepareNonceDigest: nonceDigest(req.ClientNonce), Operation: operationRecord(req.ClientNonce, wire.ActivationCompleted, packet)})
		if e != nil {
			return reject(a.Material.ActivationID, req.ClientNonce)
		}
		return packet, nil
	case wire.OperationActivationComplete:
		var req wire.ActivationComplete
		if err = open(&req); err != nil {
			return nil, err
		}
		defer clear(req.ServerNonce)
		defer clear(req.OwnerProof)
		a, e := s.db.HubActivation(req.Binding.ActivationID)
		if e != nil || a.Binding == nil || a.Pairing == nil || !reflect.DeepEqual(*a.Binding, req.Binding) || !reflect.DeepEqual(a.Binding.DevicePublic, trusted) {
			return nil, ErrAuthentication
		}
		if prior != nil {
			return replay(a.Material.ActivationID)
		}
		if !fresh(&wire.ActivationComplete{}) || a.State != wire.ActivationPrepared || nonceDigest(req.ServerNonce) != a.DeviceNonceDigest {
			return reject(a.Material.ActivationID, req.ClientNonce)
		}
		ownerNonce, e := ownerbootstrap.VerifyProof(s.ids.ClientControl, *a.Pairing, req.OwnerProof, time.Time{})
		if e != nil || ownerNonce != a.OwnerNonceDigest {
			return reject(a.Material.ActivationID, req.ClientNonce)
		}
		var credential *store.HubAccountCredential
		if a.Material.Purpose == wire.PurposeInitialActivation {
			if ValidatePassword(req.Username, setup.Name, req.Password) != nil {
				return reject(a.Material.ActivationID, req.ClientNonce)
			}
			salt := make([]byte, 32)
			if _, e = rand.Read(salt); e != nil {
				return nil, e
			}
			defer clear(salt)
			verifier, e := DerivePassword(req.Password, salt)
			if e != nil {
				return nil, e
			}
			defer clear(verifier)
			credential = &store.HubAccountCredential{AccountID: setup.AccountID, OwnerID: setup.OwnerID, Username: req.Username, Algorithm: PasswordAlgorithm, Salt: salt, Verifier: verifier, Version: 1}
		}
		r := s.activationResult(operation, route.OperationID, digest, a.Material.ActivationID, route.DeviceID, wire.ActivationCompleted, setup, epoch)
		r.RootState = wire.RootActiveState
		r.DeviceEpoch = req.Binding.DeviceEpoch
		r.LeaseState = wire.ActivationLeaseActive
		r.LeaseExpiresAt = req.Binding.LeaseExpiresAt
		r.AllowedOperations = wire.ActivationAllowedOperations()
		r.LoginRequired = true
		packet, e := seal(r)
		if e != nil {
			return nil, e
		}
		packet, e = s.db.CompleteHubActivation(store.HubActivationCompletion{ID: a.Material.ActivationID, BindingDigest: req.Binding.Digest(), OwnerNonceDigest: ownerNonce, DeviceNonceDigest: nonceDigest(req.ServerNonce), Credential: credential, Operation: operationRecord(req.ClientNonce, wire.ActivationCompleted, packet)})
		if e != nil {
			return reject(a.Material.ActivationID, req.ClientNonce)
		}
		return packet, nil
	case wire.OperationActivationStatus:
		var req wire.ActivationStatusRequest
		if err = open(&req); err != nil {
			return nil, err
		}
		a, e := s.db.HubActivation(req.ActivationID)
		if e != nil || a.Binding == nil || !reflect.DeepEqual(a.Binding.DevicePublic, trusted) || a.Binding.DeviceID != route.DeviceID || req.AccountID != setup.AccountID || req.Origin != setup.Origin {
			return nil, ErrAuthentication
		}
		if prior != nil {
			return prior.Response, nil
		}
		if !fresh(&wire.ActivationStatusRequest{}) {
			return nil, ErrAuthentication
		}
		current, epoch, e := s.db.HubAccountSetup()
		if e != nil {
			return nil, e
		}
		r := s.activationResult(operation, route.OperationID, digest, req.ActivationID, route.DeviceID, a.State, current, epoch)
		r.TargetOperation = req.TargetOperation
		r.TargetRequestID = req.TargetRequestID
		r.TargetPacketDigest = req.TargetPacketDigest
		r.TargetState = wire.ActivationAbsent
		target, e := s.db.HubOwnerOperation(setup.AccountID, route.DeviceID, req.TargetRequestID)
		if e != nil {
			return nil, e
		}
		if target != nil {
			if target.Operation != req.TargetOperation || target.Digest != req.TargetPacketDigest {
				return nil, ErrAuthentication
			}
			r.TargetState = target.State
			r.ReceiptPacket = target.Response
		}
		packet, e := seal(r)
		if e != nil {
			return nil, e
		}
		return s.db.RejectHubOwnerOperation(operationRecord(req.ClientNonce, wire.ActivationCompleted, packet))
	case wire.OperationAccountReconcile:
		var req wire.AccountReconcileRequest
		if err = open(&req); err != nil {
			return nil, err
		}
		if req.AccountID != setup.AccountID || req.Origin != setup.Origin {
			return nil, ErrAuthentication
		}
		if prior != nil {
			return prior.Response, nil
		}
		if !fresh(&wire.AccountReconcileRequest{}) {
			return nil, ErrAuthentication
		}
		original, e := wire.DecodePacket(req.OriginalPacket)
		if e != nil {
			return nil, e
		}
		originalRoute := original.Packet.Route
		b, r, e := wire.RequestRoute(hub, setup.OwnerID, route.DeviceID, originalRoute.OperationID, originalRoute.Operation, originalRoute.SessionEpoch, trusted)
		if e != nil || r != originalRoute {
			return nil, ErrAuthentication
		}
		var body any
		switch originalRoute.Operation {
		case wire.OperationLoginPrepare:
			body = &wire.LoginPrepare{}
		case wire.OperationLoginComplete:
			body = &wire.LoginComplete{}
		case wire.OperationSessionInspect:
			body = &wire.SessionInspectRequest{}
		case wire.OperationSessionLogout:
			body = &wire.LogoutRequest{}
		default:
			return nil, ErrAuthentication
		}
		if e = wire.OpenRequestAt(s.ids.ClientControl, &trusted, b, r, req.OriginalPacket, body, time.Time{}); e != nil {
			return nil, e
		}
		var account, origin string
		switch v := body.(type) {
		case *wire.LoginPrepare:
			account, origin = v.AccountID, v.Origin
		case *wire.LoginComplete:
			account, origin = v.AccountID, v.Origin
		case *wire.SessionInspectRequest:
			account, origin = v.AccountID, v.Origin
			defer clear(v.SessionToken)
		case *wire.LogoutRequest:
			account, origin = v.AccountID, v.Origin
			defer clear(v.SessionToken)
		}
		if account != setup.AccountID || origin != setup.Origin {
			return nil, ErrAuthentication
		}
		receipt, e := s.db.ReconcileHubAccountOriginal(store.HubAccountReconcileInput{AccountID: setup.AccountID, OwnerID: setup.OwnerID, DeviceID: route.DeviceID, Operation: r.Operation, RequestID: r.OperationID, RequestDigest: packetDigest(req.OriginalPacket), Epoch: epoch})
		if e != nil {
			return nil, e
		}
		d, e := s.db.HubAccountDiagnosticDevice(setup.AccountID, route.DeviceID)
		if e != nil {
			return nil, e
		}
		state := wire.ActivationRejected
		if len(receipt) > 0 {
			state = wire.ActivationCompleted
		}
		result := wire.AccountReconcileResult{Format: wire.AccountReconciledFormat, Origin: setup.Origin, HubID: setup.HubID, AccountID: setup.AccountID, OwnerID: setup.OwnerID, DeviceID: route.DeviceID, RequestID: route.OperationID, OriginalOperation: r.Operation, OriginalRequestID: r.OperationID, OriginalPacketDigest: wire.ActivationPacketDigest(req.OriginalPacket), State: state, ReceiptPacket: receipt, AccountEpoch: uint64(epoch), DeviceEpoch: uint64(d.Epoch), ObservedAt: stamp(s.requestTime())}
		packet, e := seal(result)
		if e != nil {
			return nil, e
		}
		return s.db.RejectHubOwnerOperation(operationRecord(req.ClientNonce, wire.ActivationCompleted, packet))
	}
	return nil, ErrAuthentication
}
