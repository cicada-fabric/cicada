package store

import (
	"testing"
	"time"

	"github.com/cicada-ai/cicada/internal/e2ee"
	wire "github.com/cicada-ai/cicada/internal/hubaccountwire"
)

// Synthetic Store setup with real N2/N3/bootstrap signatures. The row builder
// below is deliberately not an authenticated Node Join or an ACTIVE fixture.
func qaPairDeadlineFixture(t *testing.T, both bool) (*nativePairStoreFixture, wire.NativePairBootstrapChallenge, []*HubNativePairZeroJoin) {
	t.Helper()
	f := nativePairStore(t)
	_, _, challenge := f.prepare(t)
	_, complete, seal := f.complete(t, challenge)
	if _, err := f.f.db.ProcessHubNativePair(complete, seal); err != nil {
		t.Fatal(err)
	}
	letters := []string{"A"}
	if both {
		letters = append(letters, "B")
	}
	var joined []*HubNativePairZeroJoin
	for _, letter := range letters {
		func() {
			tx, err := f.f.db.db.Begin()
			if err != nil {
				t.Fatal(err)
			}
			defer tx.Rollback()
			pair, err := readNativePair(tx, challenge.Bootstrap.PairID)
			if err != nil {
				t.Fatal(err)
			}
			j, err := nativePairZeroJoinTx(tx, pair, wire.NativePairNodeJoin{
				ContractRevision: wire.NativePairContractRevision, PairID: pair.id,
				Slot: letter, ExpectedGeneration: 1, Runtime: "codex",
				NativeSessionID: "synthetic-qa-deadline-thread-" + letter,
				Workspace:       "/synthetic/qa-deadline/" + letter,
				EndpointName:    "Synthetic QA " + letter,
			}, "synthetic-qa-deadline-session-"+letter, f.at)
			if err != nil {
				t.Fatal(err)
			}
			if err = tx.Commit(); err != nil {
				t.Fatal(err)
			}
			joined = append(joined, j)
		}()
	}
	return f, challenge, joined
}

type qaPairLeaseSnapshot struct {
	NativeID, NativeSID, NativeCredential, NativeOwner, NativeEnd string
	NativeEpoch, NativeVersion                                    uint64
	AccessID, AccessSID, AccessCredential, AccessOwner, AccessEnd string
	AccessEpoch                                                   uint64
	MembershipID                                                  string
	MembershipRevision, EndpointJoinRevision                      uint64
	NetworkMembershipRevision, EndpointNetworkRevision            uint64
}

func qaReadPairLeases(t *testing.T, f *nativePairStoreFixture, binding string) qaPairLeaseSnapshot {
	t.Helper()
	var s qaPairLeaseSnapshot
	if err := f.f.db.db.QueryRow(`SELECT n.id,n.native_session_id,n.credential_hash,n.lease_owner,n.lease_expires_at,n.epoch,n.version,
a.id,a.native_session_id,a.credential_hash,a.lease_owner,a.lease_expires_at,a.epoch,
m.id,m.revision,eg.revision,nm.revision,en.revision
FROM session_bindings n JOIN hub_native_pair_slots_v1 s ON s.binding_id=n.id
JOIN network_access_sessions_v2 a ON a.id=s.network_access_binding_id
JOIN memberships m ON m.principal_id=n.principal_id AND m.group_id=n.group_id
JOIN endpoint_group_memberships eg ON eg.endpoint_id=n.endpoint_id AND eg.group_id=n.group_id
JOIN network_memberships_v2 nm ON nm.network_id=a.network_id AND nm.principal_id=n.principal_id
JOIN endpoint_network_memberships_v2 en ON en.network_id=a.network_id AND en.endpoint_id=n.endpoint_id
WHERE n.id=?`, binding).Scan(
		&s.NativeID, &s.NativeSID, &s.NativeCredential, &s.NativeOwner, &s.NativeEnd, &s.NativeEpoch, &s.NativeVersion,
		&s.AccessID, &s.AccessSID, &s.AccessCredential, &s.AccessOwner, &s.AccessEnd, &s.AccessEpoch,
		&s.MembershipID, &s.MembershipRevision, &s.EndpointJoinRevision, &s.NetworkMembershipRevision, &s.EndpointNetworkRevision); err != nil {
		t.Fatal(err)
	}
	return s
}

func qaPairDeadlineScope(t *testing.T, f *nativePairStoreFixture, ch wire.NativePairBootstrapChallenge, j *HubNativePairZeroJoin) NativeActorScope {
	t.Helper()
	scope := NativeActorScope{PrincipalID: j.Binding.PrincipalID, EndpointID: j.Endpoint.ID,
		GroupID: j.Binding.GroupID, NetworkID: ch.Bootstrap.NetworkID, BindingID: j.Binding.ID,
		BindingEpoch: j.Binding.Epoch, LeaseOwner: j.Binding.LeaseOwner}
	if err := f.f.db.db.QueryRow(`SELECT id,revision FROM memberships WHERE group_id=? AND principal_id=?`,
		scope.GroupID, scope.PrincipalID).Scan(&scope.MembershipID, &scope.MembershipRevision); err != nil {
		t.Fatal(err)
	}
	return scope
}

func qaPairSelfAt(t *testing.T, f *nativePairStoreFixture, ch wire.NativePairBootstrapChallenge, j *HubNativePairZeroJoin, at time.Time) error {
	t.Helper()
	scope := qaPairDeadlineScope(t, f, ch, j)
	tx, err := f.f.db.db.Begin()
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback()
	return guardNativeSelfTx(tx, scope, at)
}

func TestQANativePairJoinDeadlineIsIndependentOfLiveLeaseExpiry(t *testing.T) {
	for _, both := range []bool{false, true} {
		kind := "one_slot"
		if both {
			kind = "two_slots"
		}
		for _, edge := range []struct {
			name  string
			delta time.Duration
		}{{"before", -time.Nanosecond}, {"at", 0}, {"after", time.Nanosecond}} {
			t.Run(kind+"_"+edge.name, func(t *testing.T) {
				f, ch, joined := qaPairDeadlineFixture(t, both)
				deadline, err := time.Parse(time.RFC3339Nano, ch.Bootstrap.JoinUntil)
				if err != nil {
					t.Fatal(err)
				}
				// Real ordinary heartbeat transactions keep both original leases
				// alive beyond JoinUntil. No direct expiry edits hide this oracle.
				for _, elapsed := range []time.Duration{4 * time.Minute, 8 * time.Minute} {
					at := f.at.Add(elapsed)
					for _, j := range joined {
						if _, err := f.f.db.renewSessionBindingLease(j.Binding.ID, j.Binding.LeaseOwner, j.Binding.Epoch,
							appNodeStamp(at.Add(5*time.Minute)), func() time.Time { return at }); err != nil {
							t.Fatal("pre-deadline ordinary heartbeat failed", err)
						}
					}
				}
				j := joined[0]
				before := qaReadPairLeases(t, f, j.Binding.ID)
				for _, value := range []string{before.NativeEnd, before.AccessEnd} {
					end, err := time.Parse(time.RFC3339Nano, value)
					if err != nil || !end.After(deadline.Add(edge.delta)) {
						t.Fatal("ordinary lease expiry masks the Join deadline")
					}
				}
				at := deadline.Add(edge.delta)
				allowed := both || edge.delta < 0
				selfErr := qaPairSelfAt(t, f, ch, j, at)
				if (selfErr == nil) != allowed {
					t.Fatal("self authority ignored slot completion or JoinUntil", allowed, selfErr)
				}
				updated, renewErr := f.f.db.renewSessionBindingLease(j.Binding.ID, j.Binding.LeaseOwner, j.Binding.Epoch,
					appNodeStamp(at.Add(2*time.Hour)), func() time.Time { return at })
				if (renewErr == nil) != allowed {
					t.Fatal("renewal ignored slot completion or JoinUntil", allowed, renewErr)
				}
				after := qaReadPairLeases(t, f, j.Binding.ID)
				if !allowed {
					if before != after {
						t.Fatal("deadline rejection partly changed an original lease")
					}
					q := wire.NativePairStatusRequest{Format: wire.NativePairFormat, Context: f.context(t, at),
						SessionToken: f.f.session.Token, PairID: ch.Bootstrap.PairID}
					in, seal := f.input(t, q, at)
					packet, err := f.f.db.ProcessHubNativePair(in, seal)
					var result wire.NativePairResult
					if err != nil || wire.OpenClientResponse(f.f.device, f.f.hub, in.Packet, packet, &result) != nil ||
						result.State != wire.NativePairExpired || result.AdministrativePermission {
						t.Fatal("incomplete Pair did not report terminal expiry", err)
					}
					// Publication uses the actual production API after terminal
					// expiry is persisted, rather than replacing its wall clock.
					// The boundary oracle above separately exercised the shared
					// self guard at the precise injected writer time.
					key, err := e2ee.NewIdentity()
					if err != nil {
						t.Fatal(err)
					}
					proof, err := key.SignEndpointKeyAttestation(j.Endpoint.ID, j.Binding.PrincipalID,
						j.Binding.NodeID, j.Binding.ID, j.Binding.Epoch)
					if err != nil {
						t.Fatal(err)
					}
					terminalLeases := qaReadPairLeases(t, f, j.Binding.ID)
					if _, err := f.f.db.RegisterEndpointKeyCandidateForActor(qaPairDeadlineScope(t, f, ch, j), proof); err == nil {
						t.Fatal("expired incomplete Pair published a fresh candidate")
					}
					var candidates int
					if err := f.f.db.db.QueryRow(`SELECT count(*) FROM endpoint_key_candidates_v2 WHERE endpoint_id=?`, j.Endpoint.ID).Scan(&candidates); err != nil || candidates != 0 ||
						qaReadPairLeases(t, f, j.Binding.ID) != terminalLeases {
						t.Fatal("rejected terminal publication left candidate or lease effects", err)
					}
				} else {
					if updated.LeaseExpiresAt != ch.Bootstrap.PeerExpiresAt || after.NativeEnd != after.AccessEnd ||
						after.NativeEnd != ch.Bootstrap.PeerExpiresAt {
						t.Fatal("ordinary heartbeat did not clamp both leases to the peer ceiling")
					}
					before.NativeEnd, before.AccessEnd, before.NativeVersion = "", "", 0
					after.NativeEnd, after.AccessEnd, after.NativeVersion = "", "", 0
					if before != after {
						t.Fatal("ordinary heartbeat rotated original identity, epoch or credential")
					}
				}
				t.Log("QA_NATIVE_PAIR_JOIN_DEADLINE", kind, edge.name, "both_leases_live=true original_identity_preserved=true ACTIVE_and_Runtime_NOT_RUN=true")
			})
		}
	}
}
