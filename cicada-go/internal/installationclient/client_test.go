package installationclient

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/cicada-ai/cicada/internal/appkeys"
	"github.com/cicada-ai/cicada/internal/appvault"
	"github.com/cicada-ai/cicada/internal/e2ee"
	wire "github.com/cicada-ai/cicada/internal/hubaccountwire"
	"github.com/cicada-ai/cicada/internal/ownerbootstrap"
)

// This is an explicit synthetic TCP/crypto peer, not production Hub Store or
// Guard acceptance. Later carrier gates use the actual candidate Hub service.
type clientFixture struct {
	t           *testing.T
	mu          sync.Mutex
	now         time.Time
	available   bool
	drop        string
	errorStatus int
	tamper      bool
	server      *httptest.Server
	hubKey      *e2ee.Identity
	hub         wire.HubIdentity
	candidate   wire.InstallationCandidate
	admission   e2ee.InstallationKEMChallenge
	subjectKEM  e2ee.InstallationKEMChallenge
	requests    [][]byte
	replies     map[string][]byte
	fenced      map[string]bool
	root        string
	scope       appvault.PreRegistrationScope
	store       *appvault.PreRegistrationStore
	subject     *appkeys.Identity
	client      *Client
}

func syntheticProtector(t *testing.T) appvault.Protector {
	t.Helper()
	p, err := appvault.NewPasswordProtector([]byte("synthetic installation-client test-only password"))
	if err != nil {
		t.Fatal(err)
	}
	return p
}

func newClientFixture(t *testing.T) *clientFixture {
	t.Helper()
	hubKey, err := e2ee.NewIdentity()
	if err != nil {
		t.Fatal(err)
	}
	f := &clientFixture{t: t, now: time.Now().UTC(), available: true, hubKey: hubKey, replies: make(map[string][]byte), fenced: make(map[string]bool), root: filepath.Join(t.TempDir(), "synthetic-app")}
	f.hub = wire.HubIdentity{Contract: "android-hub-v1", HubID: "hub_synthetic_installation_client", Public: hubKey.Public(), KeyVersion: 1, Suite: ownerbootstrap.Suite}
	f.server = httptest.NewServer(http.HandlerFunc(f.serve))
	t.Cleanup(f.server.Close)
	fingerprint, err := wire.HubFingerprint(f.hub)
	if err != nil {
		t.Fatal(err)
	}
	f.scope = appvault.PreRegistrationScope{Origin: f.server.URL, HubID: f.hub.HubID, HubFingerprint: fingerprint, InstallationID: strings.Repeat("12", 16)}
	f.store, err = appvault.CreatePreRegistration(f.root, f.scope, syntheticProtector(t))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if f.client != nil {
			_ = f.client.Close()
		}
		if f.subject != nil {
			f.subject.Close()
		}
		if f.store != nil {
			_ = f.store.Close()
		}
	})
	f.openClient(t)
	return f
}

func (f *clientFixture) openClient(t *testing.T) {
	t.Helper()
	var err error
	f.subject, err = f.store.Identity()
	if err != nil {
		t.Fatal(err)
	}
	subject, err := f.subject.E2EE()
	if err != nil {
		t.Fatal(err)
	}
	f.client, err = New(Config{Origin: f.server.URL, Hub: f.hub, InstallationID: f.scope.InstallationID,
		TransportPolicy: wire.AppNodeTransportLoopbackTest, Subject: subject, Storage: f.store, HTTP: f.server.Client(),
		Now: func() time.Time { f.mu.Lock(); defer f.mu.Unlock(); return f.now }})
	if err != nil {
		t.Fatal(err)
	}
}

func (f *clientFixture) reopen(t *testing.T) {
	t.Helper()
	_ = f.client.Close()
	f.subject.Close()
	_ = f.store.Close()
	var err error
	f.store, err = appvault.OpenPreRegistration(f.root, f.scope, syntheticProtector(t))
	if err != nil {
		t.Fatal(err)
	}
	f.openClient(t)
}

func (f *clientFixture) draft() Draft {
	return Draft{Components: []string{"APP"}, Subject: e2ee.InstallationSubject{Kind: e2ee.InstallationAppSubject, Mode: e2ee.InstallationNewSubject,
		App: &e2ee.InstallationAppRef{DeviceID: "app_synthetic_independent", Public: f.subject.Public(), KeyVersion: 1, DeviceEpoch: 1}}}
}

func (f *clientFixture) serve(w http.ResponseWriter, request *http.Request) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if request.Method == http.MethodGet && request.URL.Path == wire.InstallationCapabilitiesPath {
		raw, _ := json.Marshal(wire.InstallationCapabilities{Format: wire.InstallationFormat, ContractRevision: wire.InstallationContractRevision,
			Available: f.available, ServeMode: "--hub-nodes-only", TransportPolicy: wire.AppNodeTransportLoopbackTest, Operations: wire.InstallationOperations(),
			TrustModes: []string{e2ee.InstallationFirstOOB, e2ee.InstallationExistingLocalPin}, ReadProfiles: []string{e2ee.InstallationNodeReadProfile, e2ee.InstallationPairReadProfile}})
		_, _ = w.Write(raw)
		return
	}
	raw, err := io.ReadAll(io.LimitReader(request.Body, wire.MaxInstallationReconcilePacketBytes+1))
	if err != nil {
		f.t.Error("synthetic peer could not read the bounded request")
		w.WriteHeader(400)
		return
	}
	f.requests = append(f.requests, bytes.Clone(raw))
	var header wire.InstallationPacket
	if canonical(raw, &header, wire.MaxInstallationReconcilePacketBytes) != nil || request.Method != http.MethodPost || request.URL.Path != wire.InstallationHTTPPath(header.Operation) {
		f.t.Error("synthetic peer received an invalid typed route")
		w.WriteHeader(400)
		return
	}
	// The real protected file must already retain this exact packet before
	// TCP can carry any secret-bearing request, including after restart.
	stored, _, loadErr := f.store.LoadState()
	var state durableState
	decodeErr := canonical(stored, &state, stateLimit)
	retained := state.Pending
	if header.Operation == wire.OperationInstallationReconcile {
		retained = state.Recovery
	}
	if loadErr != nil || decodeErr != nil || retained == nil || !bytes.Equal(retained.Original, raw) || len(state.AdmissionPrivate) == 0 || len(state.OOBSecret) != 32 {
		f.t.Error("request reached TCP before the protected original/key/S commit")
	}
	clear(stored)
	clearState(&state)
	if f.errorStatus != 0 {
		w.WriteHeader(f.errorStatus)
		_, _ = w.Write([]byte("SYNTHETIC_UNAUTHENTICATED_ERROR_MUST_NOT_SETTLE_OR_LEAK"))
		return
	}
	digest := e2ee.InstallationPacketDigest(raw)
	response := f.replies[digest]
	if response == nil {
		var body any
		switch header.Operation {
		case wire.OperationInstallationStart:
			var start wire.InstallationStart
			p, err := wire.OpenInstallationRequest(f.hubKey, f.hub, raw, &start, f.now)
			if err != nil || wire.OpenInstallationStartSubject(f.hubKey, f.hub, *p.Self, start.Candidate, start.SubjectSignatureProof) != nil {
				f.t.Error("actual Start admission/subject proof failed")
				w.WriteHeader(400)
				return
			}
			f.candidate = start.Candidate
			base := e2ee.InstallationKEMChallenge{Format: wire.InstallationFormat, CandidateDigest: start.Candidate.CandidateDigest, OOBCommitment: start.Candidate.OOBCommitment,
				HubID: f.hub.HubID, InstallationID: p.Self.InstallationID, AttemptID: p.Self.AttemptID, StartPacketDigest: digest,
				ChallengeID: strings.Repeat("34", 16), IssuedAt: f.now.Format(time.RFC3339Nano), ExpiresAt: f.now.Add(time.Minute).Format(time.RFC3339Nano)}
			f.admission, f.subjectKEM = base, base
			f.admission.Purpose, f.admission.RecipientKeyID, f.admission.Nonce = e2ee.InstallationAdmissionKEM, start.Candidate.Base.AdmissionPublic.ID, bytes.Repeat([]byte{0xa1}, 32)
			public, _ := e2ee.InstallationSubjectPublic(start.Candidate.Base.Subject)
			f.subjectKEM.Purpose, f.subjectKEM.RecipientKeyID, f.subjectKEM.Nonce = e2ee.InstallationSubjectKEM, public.ID, bytes.Repeat([]byte{0xb2}, 32)
			a, ae := e2ee.SealInstallationKEMChallenge(f.hubKey, start.Candidate, f.admission)
			b, be := e2ee.SealInstallationKEMChallenge(f.hubKey, start.Candidate, f.subjectKEM)
			if ae != nil || be != nil {
				f.t.Error("actual KEM challenge sealing failed")
				w.WriteHeader(500)
				return
			}
			body = wire.InstallationStartResult{Format: wire.InstallationFormat, RequestID: p.Self.RequestID, RequestPacketDigest: digest, CandidateDigest: start.Candidate.CandidateDigest,
				AttemptID: p.Self.AttemptID, Selector: "SYNTHETIC", State: wire.InstallationPending, ExpiresAt: start.Candidate.Base.ExpiresAt,
				AdmissionChallenge: wire.InstallationChallengeEnvelope{Header: e2ee.InstallationKEMHeader(f.admission), Packet: a},
				SubjectChallenge:   wire.InstallationChallengeEnvelope{Header: e2ee.InstallationKEMHeader(f.subjectKEM), Packet: b}}
		case wire.OperationInstallationProve:
			var prove wire.InstallationProve
			p, err := wire.OpenInstallationRequest(f.hubKey, f.hub, raw, &prove, f.now)
			if err != nil || !reflect.DeepEqual(p.SenderPublic, f.candidate.Base.AdmissionPublic) {
				f.t.Error("actual Prove admission authentication failed")
				w.WriteHeader(400)
				return
			}
			ad, _ := e2ee.InstallationKEMNonceDigest(f.admission)
			sd, _ := e2ee.InstallationKEMNonceDigest(f.subjectKEM)
			body, err = e2ee.VerifyInstallationPossession(f.hubKey, f.candidate, e2ee.InstallationKEMHeader(f.admission), e2ee.InstallationKEMHeader(f.subjectKEM),
				p.Self.RequestID, prove.AdmissionReceipt, prove.SubjectReceipt, ad, sd, f.now)
			if err != nil {
				f.t.Error("actual independent dual KEM/signature possession failed")
				w.WriteHeader(400)
				return
			}
		case wire.OperationInstallationPoll:
			var poll wire.InstallationPoll
			p, err := wire.OpenInstallationRequest(f.hubKey, f.hub, raw, &poll, f.now)
			if err != nil || poll.CandidateDigest != f.candidate.CandidateDigest || !reflect.DeepEqual(p.SenderPublic, f.candidate.Base.AdmissionPublic) {
				f.t.Error("actual Poll admission authentication failed")
				w.WriteHeader(400)
				return
			}
			body = wire.InstallationResult{Format: wire.InstallationFormat, Operation: p.Operation, RequestID: p.Self.RequestID, RequestPacketDigest: digest,
				AttemptID: p.Self.AttemptID, AttemptState: wire.InstallationPending, Revision: 1, Outcome: wire.InstallationCompleted, Grants: []wire.InstallationGrantRef{}, ObservedAt: f.now.Format(time.RFC3339Nano)}
		case wire.OperationInstallationReconcile:
			var q wire.InstallationReconcile
			p, err := wire.OpenInstallationRequest(f.hubKey, f.hub, raw, &q, f.now)
			if err != nil {
				f.t.Error("fresh typed reconciliation authentication failed")
				w.WriteHeader(400)
				return
			}
			var originalBody any
			switch q.OriginalOperation {
			case wire.OperationInstallationStart:
				originalBody = new(wire.InstallationStart)
			case wire.OperationInstallationProve:
				originalBody = new(wire.InstallationProve)
			case wire.OperationInstallationPoll:
				originalBody = new(wire.InstallationPoll)
			default:
				f.t.Error("unexpected synthetic recovery target")
				w.WriteHeader(400)
				return
			}
			historical, err := wire.AuthenticateInstallationOriginal(f.hubKey, f.hub, q.OriginalPacket, originalBody)
			if err != nil || !reflect.DeepEqual(historical.Header.SenderPublic, p.SenderPublic) {
				f.t.Error("historical original was not actually authenticated")
				w.WriteHeader(400)
				return
			}
			receipt := f.replies[q.OriginalPacketDigest]
			outcome := wire.InstallationCompleted
			if receipt == nil {
				if wire.InstallationIsRead(q.OriginalOperation) {
					outcome = wire.InstallationReadExpired
				} else {
					old := historical.Header
					fence := wire.InstallationResult{Format: wire.InstallationFormat, Operation: old.Operation, RequestID: old.Self.RequestID, RequestPacketDigest: q.OriginalPacketDigest,
						AttemptID: old.Self.AttemptID, AttemptState: wire.InstallationRejectedFenced, Revision: 1, Outcome: wire.InstallationRejectedFenced,
						ErrorCode: "SYNTHETIC_NO_EFFECT_FENCE", Grants: []wire.InstallationGrantRef{}, ObservedAt: f.now.Format(time.RFC3339Nano)}
					receipt, err = wire.SealInstallationResponse(f.hubKey, f.hub, q.OriginalPacket, fence)
					if err != nil {
						f.t.Error("synthetic no-effect fence could not be sealed")
						w.WriteHeader(500)
						return
					}
					f.replies[q.OriginalPacketDigest], f.fenced[q.OriginalPacketDigest] = receipt, true
				}
			}
			if f.fenced[q.OriginalPacketDigest] {
				outcome = wire.InstallationRejectedFenced
			}
			body = wire.InstallationReconciled{Format: wire.InstallationFormat, RequestID: p.Self.RequestID, RequestPacketDigest: digest,
				OriginalOperation: q.OriginalOperation, OriginalRequestID: q.OriginalRequestID, OriginalPacketDigest: q.OriginalPacketDigest,
				State: outcome, ReceiptPacket: receipt, ObservedAt: f.now.Format(time.RFC3339Nano)}
		default:
			f.t.Error("unexpected synthetic ceremony operation")
			w.WriteHeader(404)
			return
		}
		response, err = wire.SealInstallationResponse(f.hubKey, f.hub, raw, body)
		if err != nil {
			f.t.Error("actual typed response sealing failed")
			w.WriteHeader(500)
			return
		}
		f.replies[digest] = response
	}
	if f.drop == header.Operation {
		f.drop = ""
		connection, _, err := w.(http.Hijacker).Hijack()
		if err == nil {
			_ = connection.Close() // Commit reply first, lose its real TCP response.
		}
		return
	}
	if f.tamper {
		var packet wire.InstallationResponsePacket
		_ = json.Unmarshal(response, &packet)
		packet.Packet[len(packet.Packet)-1] ^= 1
		response, _ = json.Marshal(packet)
	}
	_, _ = w.Write(response)
}

func TestClientStartProvePollUseActualKeysAndProtectedOriginal(t *testing.T) {
	f := newClientFixture(t)
	if err := f.client.Start(context.Background(), f.draft()); err != nil {
		t.Fatal(err)
	}
	if _, err := f.client.Ticket(); !errors.Is(err, ErrState) {
		t.Fatal("unproved subject exposed an approval ticket")
	}
	if err := f.client.Prove(context.Background()); err != nil {
		t.Fatal(err)
	}
	ticket, err := f.client.Ticket()
	if err != nil || len(ticket) > wire.MaxInstallationTicketBytes {
		t.Fatal("single bounded secret ticket was not available after possession", err)
	}
	parsed, err := wire.DecodeInstallationTicket(ticket, f.now)
	if err != nil || wire.MatchInstallationTicket(parsed, f.candidate, f.hub, f.now) != nil {
		t.Fatal("ticket does not match the actual retained candidate")
	}
	clear(parsed.OOBSecret)
	if err := f.client.Poll(context.Background()); err != nil {
		t.Fatal(err)
	}
	status := f.client.Status()
	if !status.PossessionVerified || status.OwnerApproved || status.PendingOperation != "" || status.InstallationID != f.scope.InstallationID {
		t.Fatal("public ceremony status incorrectly claimed Owner approval or lost identity")
	}
}

func TestClientLostResponseRestoresExactPacketAndAdmission(t *testing.T) {
	f := newClientFixture(t)
	f.mu.Lock()
	f.drop = wire.OperationInstallationStart
	f.mu.Unlock()
	if err := f.client.Start(context.Background(), f.draft()); !errors.Is(err, ErrUnknown) {
		t.Fatal("lost TCP response did not remain uncertain", err)
	}
	before, _, err := f.store.LoadState()
	if err != nil {
		t.Fatal(err)
	}
	defer clear(before)
	var old durableState
	if canonical(before, &old, stateLimit) != nil {
		t.Fatal("original protected state is unavailable")
	}
	defer clearState(&old)
	f.reopen(t)
	if err := f.client.Start(context.Background(), f.draft()); !errors.Is(err, ErrPending) {
		t.Fatal("restart silently regenerated an unresolved attempt")
	}
	if err := f.client.Retry(context.Background()); err != nil {
		t.Fatal(err)
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if len(f.requests) != 2 || !bytes.Equal(f.requests[0], f.requests[1]) || !bytes.Equal(f.requests[0], old.Pending.Original) || len(f.replies) != 1 {
		t.Fatal("restart resealed the original or created a second remote reservation")
	}
	if !bytes.Equal(f.client.state.AdmissionPrivate, old.AdmissionPrivate) || !bytes.Equal(f.client.state.OOBSecret, old.OOBSecret) || !reflect.DeepEqual(f.client.state.Candidate, old.Candidate) {
		t.Fatal("restart changed the original admission, S, candidate or times")
	}
}

func TestClientUnavailableCapabilitiesMakeNoSecretPostOrPending(t *testing.T) {
	f := newClientFixture(t)
	f.mu.Lock()
	f.available = false
	f.mu.Unlock()
	if err := f.client.Start(context.Background(), f.draft()); !errors.Is(err, ErrUnavailable) {
		t.Fatal("false capabilities did not close registration")
	}
	f.mu.Lock()
	posts := len(f.requests)
	f.mu.Unlock()
	state, version, err := f.store.LoadState()
	defer clear(state)
	if err != nil || posts != 0 || len(state) != 0 || version != 0 {
		t.Fatal("unavailable Hub received secret traffic or gained a pending attempt")
	}
}

func TestClientUnauthenticatedFailuresNeverSettleOrLeakOriginal(t *testing.T) {
	for _, failure := range []string{"http-410", "tampered-pq-response"} {
		t.Run(failure, func(t *testing.T) {
			f := newClientFixture(t)
			f.mu.Lock()
			if failure == "http-410" {
				f.errorStatus = http.StatusGone
			} else {
				f.tamper = true
			}
			f.mu.Unlock()
			err := f.client.Start(context.Background(), f.draft())
			if !errors.Is(err, ErrUnknown) || strings.Contains(err.Error(), "SYNTHETIC_UNAUTHENTICATED") {
				t.Fatal("unauthenticated response settled a mutation or exported its body")
			}
			if f.client.state.Pending == nil || len(f.client.state.Pending.Response) != 0 {
				t.Fatal("uncertain original was cleared or an unauthenticated response was retained")
			}
			f.reopen(t)
			if f.client.Status().PendingOperation != wire.OperationInstallationStart {
				t.Fatal("restart discarded the uncertain Start")
			}
		})
	}
}

type failingStorage struct {
	Storage
	afterPublication bool
}

func (s failingStorage) CompareAndSwapState(version uint64, raw []byte) (uint64, error) {
	if s.afterPublication {
		if _, err := s.Storage.CompareAndSwapState(version, raw); err != nil {
			return version, err
		}
	}
	return version, errors.New("synthetic storage publication failure")
}

func TestClientStorageFailureFencesBeforeAnySecretHTTP(t *testing.T) {
	for _, after := range []bool{false, true} {
		t.Run(map[bool]string{false: "before-publication", true: "after-publication"}[after], func(t *testing.T) {
			f := newClientFixture(t)
			f.client.cfg.Storage = failingStorage{f.store, after}
			if err := f.client.Start(context.Background(), f.draft()); !errors.Is(err, ErrStorage) {
				t.Fatal("failed publication did not fence the client")
			}
			if err := f.client.Retry(context.Background()); !errors.Is(err, ErrStorage) {
				t.Fatal("poisoned in-memory state remained sendable")
			}
			f.mu.Lock()
			posts := len(f.requests)
			f.mu.Unlock()
			if posts != 0 {
				t.Fatal("secret HTTP escaped after an unconfirmed local write")
			}
			f.reopen(t)
			if after {
				if err := f.client.Retry(context.Background()); err != nil {
					t.Fatal("reopen did not recover the exact actually committed original", err)
				}
			} else if f.client.Status().PendingOperation != "" {
				t.Fatal("unpublished in-memory attempt appeared on disk")
			}
		})
	}
}

func TestClientLostProveResponseReplaysAfterChallengeExpiry(t *testing.T) {
	f := newClientFixture(t)
	if err := f.client.Start(context.Background(), f.draft()); err != nil {
		t.Fatal(err)
	}
	f.mu.Lock()
	f.drop = wire.OperationInstallationProve
	f.mu.Unlock()
	if err := f.client.Prove(context.Background()); !errors.Is(err, ErrUnknown) {
		t.Fatal("lost Prove did not retain its original", err)
	}
	before := bytes.Clone(f.client.state.Pending.Original)
	f.mu.Lock()
	f.now = f.now.Add(3 * time.Minute)
	f.mu.Unlock()
	f.reopen(t)
	if err := f.client.Retry(context.Background()); err != nil {
		t.Fatal("retained historical proof receipt was not recovered", err)
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if len(f.requests) != 3 || !bytes.Equal(f.requests[1], before) || !bytes.Equal(f.requests[2], before) || len(f.replies) != 2 || f.client.state.Possession == nil {
		t.Fatal("expired challenge caused a fresh proof, changed packet or lost receipt")
	}
}

func TestClientHistoricalStartDoesNotAuthorizeFreshExpiredPoP(t *testing.T) {
	f := newClientFixture(t)
	f.mu.Lock()
	f.drop = wire.OperationInstallationStart
	f.mu.Unlock()
	if err := f.client.Start(context.Background(), f.draft()); !errors.Is(err, ErrUnknown) {
		t.Fatal(err)
	}
	f.mu.Lock()
	f.now = f.now.Add(3 * time.Minute)
	f.mu.Unlock()
	f.reopen(t)
	if err := f.client.Retry(context.Background()); err != nil {
		t.Fatal(err)
	}
	if err := f.client.Prove(context.Background()); !errors.Is(err, ErrState) {
		t.Fatal("historical Start receipt revived an expired fresh KEM challenge")
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if len(f.requests) != 2 || !bytes.Equal(f.requests[0], f.requests[1]) {
		t.Fatal("expired challenge produced a new secret request")
	}
}
