package store

import (
	"bytes"
	"sync"
	"testing"
	"time"

	"github.com/cicada-ai/cicada/internal/e2ee"
	wire "github.com/cicada-ai/cicada/internal/hubaccountwire"
)

func TestAppNodeScopedConcurrentPrepareCompleteCASAndExactRestart(t *testing.T) {
	p := newNPTScopedStoreFixture(t)
	f := p.f
	q, err := wire.NewAppNodeScopedStatus(f.session, wire.AppNodeScopedStatusTarget{NodeID: p.context.AuthorityNodeID}, "", f.now)
	if err != nil {
		t.Fatal(err)
	}
	_, observed, _ := scopedStoreCall(t, f, q, f.now)
	other, err := New(f.path)
	if err != nil {
		t.Fatal(err)
	}
	defer other.Close()
	type attempt struct {
		body   wire.AppNodeScopedPrepare
		input  HubAppNodeScopedAuthorityInput
		seal   HubAppNodeScopedSeal
		packet []byte
		err    error
	}
	var requests [2]attempt
	for i := range requests {
		requests[i].body, err = wire.NewAppNodeScopedPrepare(f.session, observed.Result.Authority.Scope, wire.AppNodeScopedPrepareTarget{Kind: wire.AppNodeScopedTargetInitial, Code: f.code}, f.owner, f.now)
		if err != nil {
			t.Fatal(err)
		}
		requests[i].input, requests[i].seal = scopedStoreInput(t, f, requests[i].body, f.now)
	}
	stores := [2]*Store{f.db, other}
	var wg sync.WaitGroup
	for i := range requests {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			requests[i].packet, requests[i].err = stores[i].ProcessHubAppNodeScopedAuthority(requests[i].input, requests[i].seal)
		}(i)
	}
	wg.Wait()
	winner := -1
	var challenge wire.AppNodeScopedChallenge
	for i := range requests {
		if requests[i].err != nil {
			t.Fatal("concurrent prepare", requests[i].err)
		}
		result, err := wire.OpenAppNodeScopedResponse(f.device, f.hub, requests[i].input.Packet, requests[i].packet)
		if err != nil {
			t.Fatal(err)
		}
		if result.Challenge != nil {
			if winner != -1 {
				t.Fatal("two PREPARED winners")
			}
			winner = i
			challenge = *result.Challenge
		} else if result.Result == nil || result.Result.ErrorCode != "AUTHORITY_CONFLICT" {
			t.Fatal("losing prepare was not fenced")
		}
	}
	if winner == -1 {
		t.Fatal("no prepare winner")
	}
	var completions [2]struct {
		in     HubAppNodeScopedAuthorityInput
		seal   HubAppNodeScopedSeal
		packet []byte
		err    error
	}
	for i := range completions {
		body, err := wire.NewAppNodeScopedComplete(f.session, requests[winner].body, requests[winner].input.Packet, challenge, f.owner, f.now.Add(time.Second))
		if err != nil {
			t.Fatal(err)
		}
		completions[i].in, completions[i].seal = scopedStoreInput(t, f, body, f.now.Add(time.Second))
	}
	for i := range completions {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			completions[i].packet, completions[i].err = stores[i].ProcessHubAppNodeScopedAuthority(completions[i].in, completions[i].seal)
		}(i)
	}
	wg.Wait()
	completeWinner := -1
	for i := range completions {
		if completions[i].err != nil {
			t.Fatal("concurrent complete", completions[i].err)
		}
		result, err := wire.OpenAppNodeScopedResponse(f.device, f.hub, completions[i].in.Packet, completions[i].packet)
		if err != nil || result.Result == nil {
			t.Fatal(err)
		}
		if result.Result.State == wire.AppNodeScopedCompleted {
			if completeWinner != -1 {
				t.Fatal("head CAS admitted two completions")
			}
			completeWinner = i
		} else if result.Result.ErrorCode != "AUTHORITY_CONFLICT" {
			t.Fatal("losing complete was not fenced")
		}
	}
	if completeWinner == -1 {
		t.Fatal("no complete winner")
	}
	var head uint64
	var latest string
	if f.db.db.QueryRow(`SELECT head_version,latest_grant_id FROM hub_app_node_scoped_heads_v1 WHERE owner_id=? AND device_id=? AND authority_node_id=?`, f.scope.OwnerID, f.scope.DeviceID, p.context.AuthorityNodeID).Scan(&head, &latest) != nil || head != 1 || latest != challenge.Claims.GrantID {
		t.Fatal("same Node completion changed another generation")
	}
	if err := other.Close(); err != nil {
		t.Fatal(err)
	}
	if err := f.db.Close(); err != nil {
		t.Fatal(err)
	}
	f.db, err = New(f.path)
	if err != nil {
		t.Fatal(err)
	}
	retry, err := f.db.ProcessHubAppNodeScopedAuthority(completions[completeWinner].in, completions[completeWinner].seal)
	if err != nil || !bytes.Equal(retry, completions[completeWinner].packet) {
		t.Fatal("restart lost exact complete receipt", err)
	}
	// Same request ID and App key cannot change the authority Node.
	changed := requests[winner].body
	intent, err := e2ee.VerifyOwnerAppNodeScopedPreview(f.owner.Public(), changed.OwnerIntent, time.Time{})
	if err != nil {
		t.Fatal(err)
	}
	intent.Scope.AuthorityNodeID = "SYNTHETIC-other-node"
	changed.OwnerIntent, err = e2ee.SignOwnerAppNodeScopedPreview(f.owner, intent)
	if err != nil {
		t.Fatal(err)
	}
	changedIn, changedSeal := scopedStoreInput(t, f, changed, f.now.Add(2*time.Second))
	if _, err := f.db.ProcessHubAppNodeScopedAuthority(changedIn, changedSeal); err == nil {
		t.Fatal("same ID changed Node without conflict")
	}
}

func TestAppNodeScopedUnconfirmedTerminationAllowsSameNamespaceContinuation(t *testing.T) {
	for _, kind := range []string{"SELF_CANCEL", "EXPIRED"} {
		t.Run(kind, func(t *testing.T) {
			p := newNPTScopedStoreFixture(t)
			f := p.f
			query, err := wire.NewAppNodeScopedStatus(f.session, wire.AppNodeScopedStatusTarget{NodeID: p.context.AuthorityNodeID}, "", f.now)
			if err != nil {
				t.Fatal(err)
			}
			_, initial, _ := scopedStoreCall(t, f, query, f.now)
			prepare, err := wire.NewAppNodeScopedPrepare(f.session, initial.Result.Authority.Scope, wire.AppNodeScopedPrepareTarget{Kind: wire.AppNodeScopedTargetInitial, Code: f.code}, f.owner, f.now)
			if err != nil {
				t.Fatal(err)
			}
			_, proposed, _ := scopedStoreCall(t, f, prepare, f.now)
			if proposed.Challenge == nil {
				t.Fatal("initial proposal")
			}
			at := f.now.Add(time.Second)
			if kind == "SELF_CANCEL" {
				cancel, err := wire.NewAppNodeScopedCancel(f.session, p.context.AuthorityNodeID, proposed.Challenge.Claims.GrantID, 0, at)
				if err != nil {
					t.Fatal(err)
				}
				scopedStoreCall(t, f, cancel, at)
			} else {
				at = f.now.Add(6 * time.Minute)
			}
			nextQuery, err := wire.NewAppNodeScopedStatus(f.session, wire.AppNodeScopedStatusTarget{NodeID: p.context.AuthorityNodeID}, "", at)
			if err != nil {
				t.Fatal(err)
			}
			_, state, _ := scopedStoreCall(t, f, nextQuery, at)
			next, err := wire.NewAppNodeScopedPrepare(f.session, state.Result.Authority.Scope, wire.AppNodeScopedPrepareTarget{Kind: wire.AppNodeScopedTargetInitial, Code: f.code}, f.owner, at)
			if err != nil {
				t.Fatal(err)
			}
			_, result, _ := scopedStoreCall(t, f, next, at)
			if result.Challenge == nil || result.Challenge.Claims.ExpectedHeadVersion != 0 || result.Challenge.Claims.Scope.HeadVersion != 1 {
				t.Fatal("unconfirmed failure permanently locked same Node namespace")
			}
		})
	}
}

func TestAppNodeScopedCandidateVersionAndCompletedN2RemainRequired(t *testing.T) {
	t.Run("candidate namespaces", func(t *testing.T) {
		p := newNPTScopedStoreFixture(t)
		f := p.f
		legacy, err := wire.NewAppNodePrepare(f.session, f.scope, wire.AppNodePrepareTarget{Kind: wire.AppNodeTargetInitial, Code: f.code}, f.owner, f.now)
		if err != nil {
			t.Fatal(err)
		}
		_, denied, _ := f.call(t, legacy, f.now)
		if denied.Result == nil || denied.Result.ErrorCode != "CANDIDATE_UNAVAILABLE" {
			t.Fatal("v1 proof borrowed scoped Node request")
		}
		query, err := wire.NewAppNodeScopedStatus(f.session, wire.AppNodeScopedStatusTarget{NodeID: "synthetic-n3-node"}, "", f.now)
		if err != nil {
			t.Fatal(err)
		}
		_, status, _ := scopedStoreCall(t, f, query, f.now)
		scoped, err := wire.NewAppNodeScopedPrepare(f.session, status.Result.Authority.Scope, wire.AppNodeScopedPrepareTarget{Kind: wire.AppNodeScopedTargetInitial, Code: "23456789ABCD"}, f.owner, f.now)
		if err != nil {
			t.Fatal(err)
		}
		_, result, _ := scopedStoreCall(t, f, scoped, f.now)
		if result.Result == nil || result.Result.ErrorCode != "CANDIDATE_UNAVAILABLE" {
			t.Fatal("Scope2 proof borrowed v1 Node request")
		}
	})
	t.Run("login without completed N2", func(t *testing.T) {
		f := n3Fixture(t, false)
		p := newNPTScopedStoreFixtureFor(t, f, true)
		query, err := wire.NewAppNodeScopedStatus(f.session, wire.AppNodeScopedStatusTarget{NodeID: p.context.AuthorityNodeID}, "", f.now)
		if err != nil {
			t.Fatal(err)
		}
		_, status, _ := scopedStoreCall(t, f, query, f.now)
		request, err := wire.NewAppNodeScopedPrepare(f.session, status.Result.Authority.Scope, wire.AppNodeScopedPrepareTarget{Kind: wire.AppNodeScopedTargetInitial, Code: f.code}, f.owner, f.now)
		if err != nil {
			t.Fatal(err)
		}
		_, result, _ := scopedStoreCall(t, f, request, f.now)
		if result.Result == nil || result.Result.ErrorCode != "ROOT_UNAVAILABLE" || len(result.Result.Authority.AllowedOperations) != 0 {
			t.Fatal("password login promoted incomplete Owner enrollment")
		}
	})
}

func TestAppNodeScopedSecurityFencesEveryNodeWithoutMovingHeads(t *testing.T) {
	for _, kind := range []string{"OwnerKey", "ClientDevice", "ClientEpoch", "SyntheticAccountEpoch", "SyntheticAccountDeviceEpoch"} {
		t.Run(kind, func(t *testing.T) {
			f := n3Fixture(t, true)
			a := newNPTScopedStoreFixtureForNode(t, f, "SYNTHETIC-revoke-A", "6789ABCDEFGH", 0x61, true)
			aa, ap, ac := a.approve(t)
			a.call(t, a.ack(t, ap, ac, f.now.Add(4*time.Second)), f.node)
			var err error
			f.node, err = e2ee.NewIdentity()
			if err != nil {
				t.Fatal(err)
			}
			f.now = f.now.Add(6 * time.Second)
			b := newNPTScopedStoreFixtureForNode(t, f, "SYNTHETIC-revoke-B", "789ABCDEFGHJ", 0x62, true)
			ba, bp, bc := b.approve(t)
			b.call(t, b.ack(t, bp, bc, f.now.Add(4*time.Second)), f.node)
			readHeads := func() string {
				var raw string
				if f.db.db.QueryRow(`SELECT json_group_array(v) FROM(SELECT json_array(authority_node_id,head_version,latest_grant_id,provenance_id) AS v FROM hub_app_node_scoped_heads_v1 ORDER BY authority_node_id)`).Scan(&raw) != nil {
					t.Fatal("retained heads")
				}
				return raw
			}
			before := readHeads()
			switch kind {
			case "OwnerKey":
				_, err = f.db.RevokeOwnerApprovalKeyLocal(f.scope.OwnerID, f.owner.Public().ID, 1)
			case "ClientDevice":
				_, err = f.db.RevokeClientDevice(f.scope.OwnerID, f.scope.DeviceID, 1)
			case "ClientEpoch":
				_, err = f.db.AdvanceClientDeviceSessionEpoch(f.scope.OwnerID, f.scope.DeviceID, 1)
			case "SyntheticAccountEpoch":
				_, err = f.db.db.Exec(`UPDATE hub_account_config_v1 SET epoch=epoch+1 WHERE id=1`)
			case "SyntheticAccountDeviceEpoch":
				_, err = f.db.db.Exec(`UPDATE hub_account_devices_v1 SET epoch=epoch+1 WHERE account_id=? AND device_id=?`, f.scope.AccountID, f.scope.DeviceID)
			}
			if err != nil {
				t.Fatal("security transition in isolated fixture", err)
			}
			for _, approval := range []wire.NodePairTrustScopedApproval{aa, ba} {
				query, err := wire.NewAppNodeScopedStatus(f.session, wire.AppNodeScopedStatusTarget{NodeID: approval.Scope.AuthorityNodeID}, approval.GrantID, f.now.Add(5*time.Second))
				if err != nil {
					t.Fatal(err)
				}
				_, result, _ := scopedStoreCall(t, f, query, f.now.Add(5*time.Second))
				if result.Result == nil || result.Result.Authority.State != wire.AppNodeScopedRevoked || len(result.Result.Authority.AllowedOperations) != 0 || result.Result.Node != nil {
					t.Fatal("revoked Owner retained a live Node scope")
				}
			}
			if readHeads() != before {
				t.Fatal("revocation replaced original heads/provenance")
			}

		})
	}
}

func TestAppNodeScopedReadExistingKeepsOriginalProvenanceAndBudget(t *testing.T) {
	p := newNPTScopedStoreFixture(t)
	f := p.f
	a, proof, capsule := p.approve(t)
	p.call(t, p.ack(t, proof, capsule, f.now.Add(4*time.Second)), f.node)
	at := f.now.Add(16 * time.Minute)
	query, err := wire.NewAppNodeScopedStatus(f.session, wire.AppNodeScopedStatusTarget{NodeID: p.context.AuthorityNodeID}, a.GrantID, at)
	if err != nil {
		t.Fatal(err)
	}
	_, before, _ := scopedStoreCall(t, f, query, at)
	if before.Result == nil || before.Result.Authority.State != wire.AppNodeScopedExpired || before.Result.Authority.ConfirmationProvenanceID == "" {
		t.Fatal("finite INITIAL or original provenance missing")
	}
	prepare, err := wire.NewAppNodeScopedPrepare(f.session, before.Result.Authority.Scope, wire.AppNodeScopedPrepareTarget{Kind: wire.AppNodeScopedTargetPrevious, PreviousGrantID: a.GrantID}, f.owner, at)
	if err != nil {
		t.Fatal(err)
	}
	in, challenge, _ := scopedStoreCall(t, f, prepare, at)
	if challenge.Challenge == nil || challenge.Challenge.Claims.Profile != wire.AppNodeScopedProfileStatus || challenge.Challenge.Claims.ConfirmationLimit != 0 || len(challenge.Challenge.Claims.AllowedOperations) != 0 {
		t.Fatal("READ_EXISTING created another confirmation")
	}
	complete, err := wire.NewAppNodeScopedComplete(f.session, prepare, in.Packet, *challenge.Challenge, f.owner, at.Add(time.Second))
	if err != nil {
		t.Fatal(err)
	}
	scopedStoreCall(t, f, complete, at.Add(time.Second))
	status, err := wire.NewAppNodeScopedStatus(f.session, wire.AppNodeScopedStatusTarget{NodeID: p.context.AuthorityNodeID}, challenge.Challenge.Claims.GrantID, at.Add(2*time.Second))
	if err != nil {
		t.Fatal(err)
	}
	_, after, _ := scopedStoreCall(t, f, status, at.Add(2*time.Second))
	if after.Result == nil || wire.ValidateAppNodeScopedLiveResult(*after.Result, challenge.Challenge.Claims, f.hub, at.Add(2*time.Second)) != nil || after.Result.Authority.ConfirmationProvenanceID != before.Result.Authority.ConfirmationProvenanceID || after.Result.Authority.Counters.LastRequestSequence != 1 || after.Result.Authority.Counters.NextResponseSequence != 2 || after.Result.Node == nil || after.Result.Node.NodeID != p.context.AuthorityNodeID {
		t.Fatal("READ_EXISTING moved original proof/counters or lost exact Node")
	}
	if _, err := wire.SealAppNodeScopedConfirmation(f.device, f.hub, challenge.Challenge.Claims, f.code, 2, at.Add(2*time.Second)); err == nil {
		t.Fatal("READ_EXISTING could seal another confirmation")
	}
}

func TestAppNodeScopedCodeStatusReconcileAfterAnonymousGC(t *testing.T) {
	p := newNPTScopedStoreFixture(t)
	f := p.f
	status, err := wire.NewAppNodeScopedStatus(f.session, wire.AppNodeScopedStatusTarget{CandidateCode: f.code}, "", f.now)
	if err != nil {
		t.Fatal(err)
	}
	original, observed, originalReceipt := scopedStoreCall(t, f, status, f.now)
	if observed.Result == nil || observed.Result.Authority.Scope.AuthorityNodeID != p.context.AuthorityNodeID {
		t.Fatal("code did not resolve original Node")
	}
	_, originalSeal := scopedStoreInput(t, f, status, f.now)
	at := f.now.Add(21 * time.Minute)
	tx, err := f.db.db.Begin()
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback()
	if err := nodePairGC(tx, at); err != nil {
		t.Fatal(err)
	}
	if err := tx.Commit(); err != nil {
		t.Fatal(err)
	}
	var count int
	if f.db.db.QueryRow(`SELECT count(*) FROM node_control_key_requests_v1 WHERE id=?`, p.context.Candidate.RequestID).Scan(&count) != nil || count != 0 {
		t.Fatal("actual anonymous GC did not remove original candidate")
	}
	// Leave the original encrypted read in its separate cache: GC settlement
	// must not return these old bytes after their Node mapping is gone.
	var retained []byte
	if f.db.db.QueryRow(`SELECT response_packet FROM hub_app_node_reads_v1 WHERE operation_id=?`, status.Context.RequestID).Scan(&retained) != nil || !bytes.Equal(retained, originalReceipt) {
		t.Fatal("original read cache fixture was not retained")
	}
	query, err := wire.NewAppNodeScopedReconcile(f.session, p.context.AuthorityNodeID, wire.AppNodeScopedOriginalAuthority, "", original.Packet, at)
	if err != nil {
		t.Fatal(err)
	}
	in, seal := scopedStoreInput(t, f, query, at)
	in.Original, in.OriginalSeal = &original, originalSeal
	packet, err := f.db.ProcessHubAppNodeScopedAuthority(in, seal)
	if err != nil {
		t.Fatal("collected code read could not settle", err)
	}
	result, err := wire.OpenAppNodeScopedResponse(f.device, f.hub, in.Packet, packet)
	if err != nil || result.Reconciled == nil || result.Reconciled.State != wire.AppNodeScopedReadExpired || len(result.Reconciled.ReceiptPacket) != 0 || result.Reconciled.AuthorityNodeID != p.context.AuthorityNodeID {
		t.Fatal("GC read returned old receipt or authority", err)
	}
	retry, err := f.db.ProcessHubAppNodeScopedAuthority(in, seal)
	if err != nil || !bytes.Equal(packet, retry) {
		t.Fatal("GC settlement exact retry changed", err)
	}
	if f.db.db.QueryRow(`SELECT count(*) FROM hub_app_node_operations_v1 WHERE operation_id=?`, status.Context.RequestID).Scan(&count) != nil || count != 0 {
		t.Fatal("GC read created a mutation fence")
	}
	// A storage/query failure is not evidence of a collected candidate.
	if _, err := f.db.db.Exec(`DROP TABLE node_control_key_requests_v1`); err != nil {
		t.Fatal(err)
	}
	query, err = wire.NewAppNodeScopedReconcile(f.session, p.context.AuthorityNodeID, wire.AppNodeScopedOriginalAuthority, "", original.Packet, at.Add(time.Second))
	if err != nil {
		t.Fatal(err)
	}
	in, seal = scopedStoreInput(t, f, query, at.Add(time.Second))
	in.Original, in.OriginalSeal = &original, originalSeal
	if response, err := f.db.ProcessHubAppNodeScopedAuthority(in, seal); err == nil || len(response) != 0 {
		t.Fatal("database failure was treated as anonymous GC")
	}
}
