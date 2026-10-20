// Package hubauth authenticates limited Hub account actors independently of
// Control business and independently of Owner approval/Client manager grants.
package hubauth

import (
	"context"
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"errors"
	"reflect"
	"sync"
	"time"

	"github.com/cicada-ai/cicada/internal/e2ee"
	wire "github.com/cicada-ai/cicada/internal/hubaccountwire"
	"github.com/cicada-ai/cicada/internal/hubidentity"
	"github.com/cicada-ai/cicada/internal/store"
)

var ErrBusy = errors.New("Hub account authentication is busy")

type Service struct {
	db                *store.Store
	ids               hubidentity.Set
	admitted, workers chan struct{}
	rateMu            sync.Mutex
	tokens            float64
	last              time.Time
	requestNow        func() time.Time
	appNodeAuthority  bool
}

func NewService(db *store.Store, ids hubidentity.Set) (*Service, error) {
	if db == nil || ids.Peer == nil || ids.ClientControl == nil || ids.NodeControl == nil {
		return nil, ErrAuthentication
	}
	if e := db.ReconcileHubAccountRestore(); e != nil {
		return nil, e
	}
	return &Service{db: db, ids: ids, admitted: make(chan struct{}, 6), workers: make(chan struct{}, 2), tokens: 12, last: time.Now(), requestNow: time.Now}, nil
}

func (s *Service) requestTime() time.Time {
	if s.requestNow != nil {
		return s.requestNow().UTC()
	}
	return time.Now().UTC()
}
func (s *Service) HubIdentity() (wire.HubIdentity, error) {
	id, e := s.db.GetClientHubID()
	if e != nil {
		return wire.HubIdentity{}, e
	}
	return wire.HubIdentity{Contract: "android-hub-v1", HubID: id, Public: s.ids.ClientControl.Public(), KeyVersion: 1, Suite: "ML-KEM-768+ML-DSA-65+AES-256-GCM"}, nil
}
func (s *Service) ExpectedOrigin() (string, error) {
	if s.appNodeAuthority {
		setup, e := s.db.GetHubOwnerSetup()
		if e != nil || setup == nil {
			return "", ErrAuthentication
		}
		return setup.Origin, nil
	}
	setup, _, e := s.db.HubAccountSetup()
	if e != nil {
		return "", e
	}
	return setup.Origin, nil
}
func (s *Service) issueCard(cancel bool) (*wire.ClaimCard, error) {
	setup, epoch, e := s.db.HubAccountSetup()
	if e != nil || setup.RootEverEstablished {
		return nil, ErrAuthentication
	}
	if _, e = s.db.HubAccountCredential(setup.AccountID); e == nil {
		return nil, ErrAuthentication
	}
	hub, e := s.HubIdentity()
	if e != nil {
		return nil, e
	}
	fp, e := wire.HubFingerprint(hub)
	if e != nil {
		return nil, e
	}
	id, e := wire.NewRequestID()
	if e != nil {
		return nil, e
	}
	code := make([]byte, 32)
	if _, e = rand.Read(code); e != nil {
		return nil, e
	}
	defer clear(code)
	at := time.Now().UTC()
	card := wire.ClaimCard{Format: wire.ClaimCardFormat, Version: 1, Purpose: wire.PurposeInitialClaim, Origin: setup.Origin, AllowLoopbackHTTP: setup.AllowLoopbackHTTP, HubID: setup.HubID, HubFingerprint: fp, AccountID: setup.AccountID, OwnerID: setup.OwnerID, ClaimID: id, Code: base64.RawURLEncoding.EncodeToString(code), IssuedAt: stamp(at), ExpiresAt: stamp(at.Add(time.Hour))}
	if wire.ValidateClaimCard(card, hub, at) != nil {
		return nil, ErrAuthentication
	}
	if e = s.db.IssueHubAccountClaimLocal(store.HubAccountClaim{ID: id, AccountID: setup.AccountID, OwnerID: setup.OwnerID, HubID: setup.HubID, Origin: setup.Origin, HubPin: fp, CodeDigest: codeDigest(card), Epoch: epoch, ExpiresAt: card.ExpiresAt}, cancel); e != nil {
		return nil, e
	}
	return &card, nil
}

// IssueClaimLocal is a private deployment-channel operation, never HTTP.
func (s *Service) IssueClaimLocal(cancel bool) (*wire.ClaimCard, error) { return s.issueCard(cancel) }
func codeDigest(card wire.ClaimCard) string {
	b, _ := json.Marshal(card)
	defer clear(b)
	return store.AccountDigest("claim-code", b)
}
func hashBody(v any) string {
	b, _ := json.Marshal(v)
	defer clear(b)
	return store.AccountDigest("challenge", b)
}
func packetDigest(b []byte) string    { return store.AccountDigest("packet", b) }
func nonceDigest(nonce []byte) string { return store.AccountDigest("client-nonce", nonce) }
func stamp(t time.Time) string        { return t.UTC().Format(time.RFC3339Nano) }
func (s *Service) rateAllowed() bool {
	s.rateMu.Lock()
	defer s.rateMu.Unlock()
	at := time.Now()
	s.tokens += at.Sub(s.last).Seconds() * 4
	s.last = at
	if s.tokens > 12 {
		s.tokens = 12
	}
	if s.tokens < 1 {
		return false
	}
	s.tokens--
	return true
}
func (s *Service) acquire(ctx context.Context) (func(), error) {
	if !s.rateAllowed() {
		return nil, ErrBusy
	}
	select {
	case s.admitted <- struct{}{}:
	default:
		return nil, ErrBusy
	}
	select {
	case s.workers <- struct{}{}:
		return func() { <-s.workers; <-s.admitted }, nil
	case <-ctx.Done():
		<-s.admitted
		return nil, ErrBusy
	}
}

// Handle keeps packet preflight/current registry checks ahead of expensive PQ
// work. Tokens, passwords and KEM challenge nonces stay inside sealed bodies.
func (s *Service) Handle(ctx context.Context, operation string, raw []byte) (response []byte, err error) {
	if operation == wire.OperationOwnerEndpointRead {
		if s == nil || !s.appNodeAuthority || len(raw) == 0 || len(raw) > wire.MaxPacketBytes {
			return nil, ErrAuthentication
		}
		return s.handleOwnerEndpointRead(ctx, raw)
	}
	if wire.NativePairHTTPPath(operation) != "" {
		if s == nil || len(raw) == 0 || len(raw) > wire.MaxNativePairReconcilePacketBytes {
			return nil, ErrAuthentication
		}
		return s.handleNativePair(ctx, operation, raw)
	}
	if s == nil || len(raw) == 0 || len(raw) > wire.MaxPacketBytes {
		return nil, ErrAuthentication
	}
	if wire.AppNodeHTTPPath(operation) != "" {
		if !s.appNodeAuthority {
			return nil, ErrAuthentication
		}
		return s.handleAppNode(ctx, operation, raw)
	}
	if wire.ActivationHTTPPath(operation) != "" {
		return s.handleExtension(ctx, operation, raw)
	}
	p, e := wire.PreflightRequest(raw, operation)
	if e != nil {
		return nil, ErrAuthentication
	}
	setup, epoch, e := s.db.HubAccountSetup()
	if e != nil {
		return nil, ErrAuthentication
	}
	hub, e := s.HubIdentity()
	if e != nil {
		return nil, ErrAuthentication
	}
	route := p.Packet.Route
	if route.HubID != setup.HubID || route.OwnerID != setup.OwnerID {
		return nil, ErrAuthentication
	}
	trusted := p.SenderPublicIdentity
	var expected *e2ee.PublicIdentity
	var attempt *store.HubAccountAttempt
	var device *store.HubAccountDevice
	scopeEpoch := uint64(1)
	switch operation {
	case wire.OperationClaimPrepare:
		if setup.RootEverEstablished {
			return nil, ErrAuthentication
		}
		if _, e = s.db.HubAccountCredential(setup.AccountID); e == nil {
			return nil, ErrAuthentication
		}
	case wire.OperationClaimComplete:
		attempt, e = s.db.HubAccountAttemptForDevice(setup.AccountID, route.DeviceID, "CLAIM")
		if e != nil || attempt.Epoch != epoch || attempt.State == "CANCELLED" {
			return nil, ErrAuthentication
		}
		trusted = attempt.DevicePublic
		expected = &trusted
	case wire.OperationLoginPrepare, wire.OperationLoginComplete, wire.OperationSessionInspect, wire.OperationSessionLogout:
		device, e = s.db.HubAccountDevice(setup.AccountID, route.DeviceID)
		if e != nil {
			return nil, ErrAuthentication
		}
		trusted = device.Public
		expected = &trusted
		if operation == wire.OperationSessionInspect || operation == wire.OperationSessionLogout {
			scopeEpoch = uint64(epoch)
		}
	default:
		return nil, ErrAuthentication
	}
	binding, expectedRoute, e := wire.RequestRoute(hub, setup.OwnerID, route.DeviceID, route.OperationID, operation, scopeEpoch, trusted)
	if e != nil || expectedRoute != route || !reflect.DeepEqual(p.SenderPublicIdentity, trusted) {
		return nil, ErrAuthentication
	}
	digest := packetDigest(raw)
	if operation == wire.OperationClaimComplete && attempt.State == "CONSUMED" {
		receipt, e := s.db.CachedHubAccountCompletion(attempt.ID, route.OperationID, digest)
		if e != nil {
			return nil, ErrAuthentication
		}
		return receipt, nil
	}
	// Only a digest that already names a durable accepted receipt may skip
	// request freshness. OpenRequestAt still verifies the original device proof,
	// route, canonical body and request coordinates before a receipt is returned.
	acceptedReplay := false
	switch operation {
	case wire.OperationLoginComplete:
		acceptedReplay, e = s.db.HubAccountLoginCompletionReplayCandidate(setup.AccountID, route.DeviceID, route.OperationID, digest, epoch, device.Epoch)
	case wire.OperationSessionInspect, wire.OperationSessionLogout:
		acceptedReplay, e = s.db.HubAccountSessionRequestReplayCandidate(setup.AccountID, route.DeviceID, operation, route.OperationID, digest, epoch, device.Epoch)
	}
	if e != nil {
		return nil, ErrAuthentication
	}
	release, e := s.acquire(ctx)
	if e != nil {
		return nil, e
	}
	defer release()
	defer func() {
		if err != nil && !errors.Is(err, ErrBusy) {
			err = ErrAuthentication
		}
	}()
	open := func(out any) error {
		at := s.requestTime()
		if acceptedReplay {
			at = time.Time{}
		}
		return wire.OpenRequestAt(s.ids.ClientControl, expected, binding, expectedRoute, raw, out, at)
	}
	seal := func(body any) ([]byte, error) { return wire.SealResponse(s.ids.ClientControl, trusted, route, body) }
	switch operation {
	case wire.OperationClaimPrepare:
		var req wire.ClaimPrepare
		if e = open(&req); e != nil {
			return nil, e
		}
		card := req.Claim
		c, e := s.db.HubAccountClaim(card.ClaimID)
		if e != nil || c.AccountID != setup.AccountID || c.OwnerID != setup.OwnerID || c.Origin != setup.Origin || card.AllowLoopbackHTTP != setup.AllowLoopbackHTTP || c.HubPin != card.HubFingerprint || c.ExpiresAt != card.ExpiresAt || c.Epoch != epoch {
			return nil, ErrAuthentication
		}
		got := codeDigest(card)
		if subtle.ConstantTimeCompare([]byte(got), []byte(c.CodeDigest)) != 1 {
			return nil, ErrAuthentication
		}
		if c.State == "PREPARED" {
			a, e := s.db.HubAccountAttempt(c.AttemptID)
			if e != nil || a.PrepareID != req.RequestID || a.PrepareDigest != digest || !reflect.DeepEqual(a.DevicePublic, trusted) {
				return nil, ErrAuthentication
			}
			return a.ChallengePacket, nil
		}
		if c.State != "ISSUED" {
			return nil, ErrAuthentication
		}
		at := time.Now().UTC()
		expiry := at.Add(wire.MaxClaimChallengeLifetime)
		ce, _ := time.Parse(time.RFC3339Nano, c.ExpiresAt)
		if expiry.After(ce) {
			expiry = ce
		}
		id, e := wire.NewRequestID()
		if e != nil {
			return nil, e
		}
		nonce, e := wire.NewNonce()
		if e != nil {
			return nil, e
		}
		defer clear(nonce)
		ch := wire.ClaimChallenge{Format: wire.ClaimChallengeFormat, Purpose: wire.PurposeInitialClaim, Origin: setup.Origin, HubID: setup.HubID, AccountID: setup.AccountID, OwnerID: setup.OwnerID, ClaimID: c.ID, AttemptID: id, DeviceID: req.DeviceID, DeviceKeyID: trusted.ID, DeviceKeyFingerprint: req.DeviceKeyFingerprint, PrepareRequestID: req.RequestID, ClientNonce: req.ClientNonce, ServerNonce: nonce, AccountEpoch: uint64(epoch), DeviceEpoch: 1, IssuedAt: stamp(at), ExpiresAt: stamp(expiry)}
		packet, e := seal(ch)
		if e != nil {
			return nil, e
		}
		a := store.HubAccountAttempt{ID: id, Purpose: "CLAIM", ClaimID: c.ID, AccountID: setup.AccountID, OwnerID: setup.OwnerID, DeviceID: req.DeviceID, DevicePublic: trusted, Epoch: epoch, DeviceEpoch: 1, PrepareID: req.RequestID, PrepareDigest: digest, PrepareNonceDigest: nonceDigest(req.ClientNonce), ChallengeDigest: hashBody(ch), ChallengePacket: packet, ExpiresAt: ch.ExpiresAt}
		if e = s.db.SaveHubAccountAttempt(a); e != nil {
			prior, pe := s.db.HubAccountAttemptByPrepare(req.RequestID)
			if pe == nil && prior.PrepareDigest == digest {
				return prior.ChallengePacket, nil
			}
			return nil, e
		}
		return packet, nil
	case wire.OperationClaimComplete:
		var req wire.ClaimComplete
		if e = open(&req); e != nil {
			return nil, e
		}
		if req.Origin != setup.Origin || req.AccountID != setup.AccountID || req.AttemptID != attempt.ID || req.AccountEpoch != uint64(epoch) || req.DeviceEpoch != uint64(attempt.DeviceEpoch) || req.ClaimID != attempt.ClaimID {
			return nil, ErrAuthentication
		}
		ch := wire.ClaimChallenge{Format: wire.ClaimChallengeFormat, Purpose: wire.PurposeInitialClaim, Origin: req.Origin, HubID: req.HubID, AccountID: req.AccountID, OwnerID: req.OwnerID, ClaimID: req.ClaimID, AttemptID: req.AttemptID, DeviceID: req.DeviceID, DeviceKeyID: req.DeviceKeyID, DeviceKeyFingerprint: req.DeviceKeyFingerprint, PrepareRequestID: req.PrepareRequestID, ClientNonce: req.PrepareClientNonce, ServerNonce: req.ServerNonce, AccountEpoch: req.AccountEpoch, DeviceEpoch: req.DeviceEpoch, IssuedAt: req.ChallengeIssuedAt, ExpiresAt: req.ChallengeExpiresAt}
		if hashBody(ch) != attempt.ChallengeDigest {
			return nil, ErrAuthentication
		}
		if ValidatePassword(req.Username, setup.Name, req.Password) != nil {
			return nil, ErrAuthentication
		}
		for _, key := range []*e2ee.Identity{s.ids.Peer, s.ids.ClientControl, s.ids.NodeControl} {
			if req.OwnerPublicIdentity.ID == key.Public().ID {
				return nil, ErrAuthentication
			}
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
		fp, e := e2ee.OwnerDevicePublicKeyFingerprint(req.OwnerPublicIdentity)
		if e != nil {
			return nil, e
		}
		receipt := wire.ClaimReceipt{Format: wire.ClaimReceiptFormat, Purpose: wire.PurposeInitialClaim, Origin: setup.Origin, HubID: setup.HubID, AccountID: setup.AccountID, OwnerID: setup.OwnerID, ClaimID: req.ClaimID, AttemptID: req.AttemptID, RequestID: req.RequestID, DeviceID: req.DeviceID, DeviceKeyID: req.DeviceKeyID, DeviceKeyFingerprint: req.DeviceKeyFingerprint, AccountEpoch: req.AccountEpoch, DeviceEpoch: req.DeviceEpoch, State: wire.ClaimPendingState, OwnerKeyID: req.OwnerPublicIdentity.ID, OwnerFingerprint: fp, RootState: wire.RootPendingState, CompletedAt: stamp(time.Now())}
		packet, e := seal(receipt)
		if e != nil {
			return nil, e
		}
		return s.db.CompleteHubAccountClaim(store.HubAccountCompleteInput{AttemptID: req.AttemptID, ChallengeDigest: hashBody(ch), RequestID: req.RequestID, RequestDigest: digest, CompleteNonceDigest: nonceDigest(req.ClientNonce), Credential: store.HubAccountCredential{AccountID: setup.AccountID, OwnerID: setup.OwnerID, Username: req.Username, Algorithm: PasswordAlgorithm, Salt: salt, Verifier: verifier, Version: 1}, OwnerPublic: req.OwnerPublicIdentity, OwnerFingerprint: fp, Receipt: packet})
	case wire.OperationLoginPrepare:
		var req wire.LoginPrepare
		if e = open(&req); e != nil {
			return nil, e
		}
		cred, e := s.db.HubAccountCredential(setup.AccountID)
		if e != nil || req.AccountID != setup.AccountID || req.Origin != setup.Origin || req.Username != cred.Username {
			return nil, ErrAuthentication
		}
		if prior, e := s.db.HubAccountAttemptByPrepare(req.RequestID); e == nil {
			current, ce := s.db.HubAccountAttempt(prior.ID)
			if ce != nil || current.PrepareDigest != digest || current.State != "PENDING" || !reflect.DeepEqual(current.DevicePublic, trusted) {
				return nil, ErrAuthentication
			}
			return current.ChallengePacket, nil
		}
		at := time.Now().UTC()
		id, e := wire.NewRequestID()
		if e != nil {
			return nil, e
		}
		nonce, e := wire.NewNonce()
		if e != nil {
			return nil, e
		}
		defer clear(nonce)
		ch := wire.LoginChallenge{Format: wire.LoginChallengeFormat, Purpose: wire.PurposeAccountLogin, Username: req.Username, Origin: setup.Origin, HubID: setup.HubID, AccountID: setup.AccountID, OwnerID: setup.OwnerID, AttemptID: id, DeviceID: req.DeviceID, DeviceKeyID: req.DeviceKeyID, DeviceKeyFingerprint: req.DeviceKeyFingerprint, PrepareRequestID: req.RequestID, ClientNonce: req.ClientNonce, ServerNonce: nonce, AccountEpoch: uint64(epoch), DeviceEpoch: uint64(device.Epoch), IssuedAt: stamp(at), ExpiresAt: stamp(at.Add(wire.MaxLoginChallengeLifetime))}
		packet, e := seal(ch)
		if e != nil {
			return nil, e
		}
		if e = s.db.SaveHubAccountAttempt(store.HubAccountAttempt{ID: id, Purpose: "LOGIN", AccountID: setup.AccountID, OwnerID: setup.OwnerID, DeviceID: req.DeviceID, DevicePublic: trusted, Epoch: epoch, DeviceEpoch: device.Epoch, PrepareID: req.RequestID, PrepareDigest: digest, PrepareNonceDigest: nonceDigest(req.ClientNonce), ChallengeDigest: hashBody(ch), ChallengePacket: packet, ExpiresAt: ch.ExpiresAt}); e != nil {
			prior, pe := s.db.HubAccountAttemptByPrepare(req.RequestID)
			if pe == nil && prior.PrepareDigest == digest {
				return prior.ChallengePacket, nil
			}
			return nil, e
		}
		return packet, nil
	case wire.OperationLoginComplete:
		var req wire.LoginComplete
		if e = open(&req); e != nil {
			return nil, e
		}
		a, e := s.db.HubAccountAttempt(req.AttemptID)
		if e != nil || a.Purpose != "LOGIN" || a.AccountID != setup.AccountID || a.DeviceID != device.DeviceID || req.Origin != setup.Origin || req.AccountID != setup.AccountID || req.AccountEpoch != uint64(epoch) || req.DeviceEpoch != uint64(device.Epoch) {
			return nil, ErrAuthentication
		}
		if a.State == "CONSUMED" {
			return s.db.CachedHubAccountCompletion(a.ID, req.RequestID, digest)
		}
		ch := wire.LoginChallenge{Format: wire.LoginChallengeFormat, Purpose: wire.PurposeAccountLogin, Username: req.Username, Origin: req.Origin, HubID: req.HubID, AccountID: req.AccountID, OwnerID: req.OwnerID, AttemptID: req.AttemptID, DeviceID: req.DeviceID, DeviceKeyID: req.DeviceKeyID, DeviceKeyFingerprint: req.DeviceKeyFingerprint, PrepareRequestID: req.PrepareRequestID, ClientNonce: req.PrepareClientNonce, ServerNonce: req.ServerNonce, AccountEpoch: req.AccountEpoch, DeviceEpoch: req.DeviceEpoch, IssuedAt: req.ChallengeIssuedAt, ExpiresAt: req.ChallengeExpiresAt}
		if hashBody(ch) != a.ChallengeDigest {
			return nil, ErrAuthentication
		}
		c, e := s.db.HubAccountCredential(setup.AccountID)
		if e != nil || req.Username != c.Username || c.Algorithm != PasswordAlgorithm || !CheckPassword(req.Password, c.Salt, c.Verifier) {
			return nil, ErrAuthentication
		}
		token, e := wire.NewNonce()
		if e != nil {
			return nil, e
		}
		defer clear(token)
		id, e := wire.NewRequestID()
		if e != nil {
			return nil, e
		}
		at := time.Now().UTC()
		receipt := wire.SessionReceipt{Format: wire.SessionReceiptFormat, Purpose: wire.PurposeAccountSession, Origin: setup.Origin, HubID: setup.HubID, AccountID: setup.AccountID, OwnerID: setup.OwnerID, DeviceID: req.DeviceID, DeviceKeyID: req.DeviceKeyID, DeviceKeyFingerprint: req.DeviceKeyFingerprint, SessionToken: token, AccountEpoch: uint64(epoch), DeviceEpoch: uint64(device.Epoch), RequestID: req.RequestID, IssuedAt: stamp(at), ExpiresAt: stamp(at.Add(wire.MaxSessionLifetime))}
		packet, e := seal(receipt)
		if e != nil {
			return nil, e
		}
		return s.db.CompleteHubAccountLogin(a.ID, hashBody(ch), req.RequestID, digest, nonceDigest(req.ClientNonce), store.HubAccountSession{ID: id, AccountID: setup.AccountID, OwnerID: setup.OwnerID, DeviceID: req.DeviceID, Epoch: epoch, DeviceEpoch: device.Epoch, CredentialVersion: c.Version, TokenDigest: store.AccountDigest("session-token", token), ExpiresAt: receipt.ExpiresAt}, packet)
	case wire.OperationSessionInspect, wire.OperationSessionLogout:
		var token []byte
		var requestNonce []byte
		var account, origin string
		var ae, de uint64
		if operation == wire.OperationSessionInspect {
			var req wire.SessionInspectRequest
			if e = open(&req); e != nil {
				return nil, e
			}
			token, requestNonce, account, origin, ae, de = req.SessionToken, req.ClientNonce, req.AccountID, req.Origin, req.AccountEpoch, req.DeviceEpoch
		} else {
			var req wire.LogoutRequest
			if e = open(&req); e != nil {
				return nil, e
			}
			token, requestNonce, account, origin, ae, de = req.SessionToken, req.ClientNonce, req.AccountID, req.Origin, req.AccountEpoch, req.DeviceEpoch
		}
		defer clear(token)
		defer clear(requestNonce)
		if account != setup.AccountID || origin != setup.Origin || ae != uint64(epoch) || de != uint64(device.Epoch) {
			return nil, ErrAuthentication
		}
		tokenDigest := store.AccountDigest("session-token", token)
		session, e := s.db.HubAccountSessionByTokenDigest(tokenDigest)
		if e != nil {
			if operation == wire.OperationSessionLogout {
				return s.db.HubAccountRevokedLogoutReceipt(tokenDigest, setup.AccountID, device.DeviceID, epoch, device.Epoch, route.OperationID, digest)
			}
			return nil, ErrAuthentication
		}
		if session.AccountID != setup.AccountID || session.DeviceID != device.DeviceID {
			return nil, ErrAuthentication
		}
		cached, e := s.db.HubAccountCachedRequest(session.ID, route.OperationID, operation, digest)
		if e != nil {
			return nil, e
		}
		if cached != nil {
			return cached, nil
		}
		var body any
		if operation == wire.OperationSessionLogout {
			body = wire.LogoutReceipt{Format: wire.LogoutReceiptFormat, Purpose: wire.PurposeAccountSession, Origin: setup.Origin, HubID: setup.HubID, AccountID: setup.AccountID, OwnerID: setup.OwnerID, DeviceID: device.DeviceID, AccountEpoch: uint64(epoch), DeviceEpoch: uint64(device.Epoch), RequestID: route.OperationID, State: wire.SessionRevokedState, LoggedOutAt: stamp(time.Now())}
		} else {
			status, e := s.db.HubAccountStatus(setup.AccountID)
			if e != nil {
				return nil, e
			}
			list := []wire.LoginDeviceSummary{}
			for _, d := range status.Devices {
				list = append(list, wire.LoginDeviceSummary{DeviceID: d.DeviceID, DeviceKeyID: d.KeyID, DeviceKeyFingerprint: d.Fingerprint, State: d.State, DeviceEpoch: uint64(d.Epoch), CreatedAt: d.CreatedAt})
			}
			body = wire.SessionInspection{Format: wire.SessionInspectionFormat, Purpose: wire.PurposeAccountSession, Origin: setup.Origin, HubID: setup.HubID, AccountID: setup.AccountID, OwnerID: setup.OwnerID, ActorDeviceID: device.DeviceID, ActorDeviceEpoch: uint64(device.Epoch), RequestID: route.OperationID, State: wire.SessionActiveState, Devices: list, InspectedAt: stamp(time.Now()), Username: status.Username, RootState: status.RootState, RootActive: status.RootActive, OwnerKeyID: status.OwnerPublic.ID, OwnerFingerprint: status.OwnerFingerprint}
		}
		packet, e := seal(body)
		if e != nil {
			return nil, e
		}
		return s.db.CompleteHubAccountRequest(session.ID, route.OperationID, operation, digest, nonceDigest(requestNonce), packet, operation == wire.OperationSessionLogout)
	}
	return nil, ErrAuthentication
}
