package fabric

import (
	"errors"
	"testing"
	"time"
)

func TestLiveRenewedSessionSurvivesLegacyEndpointHousekeeping(t *testing.T) {
	service, persistence, group := newFabricTestService(t)
	joined, err := service.Join(JoinInput{
		GroupID: group.ID, PrincipalName: "present", EndpointName: "present",
		Harness: "codex", NativeSessionID: "native-present", NodeID: "node-present",
	})
	if err != nil {
		t.Fatal(err)
	}
	first, err := service.AuthenticateForGroup(joined.SessionToken, group.ID)
	if err != nil {
		t.Fatal(err)
	}
	renewed, err := service.RenewForGroup(joined.SessionToken, group.ID, 0)
	if err != nil {
		t.Fatal(err)
	}
	if renewed.BindingID != first.BindingID || renewed.BindingEpoch != first.BindingEpoch ||
		renewed.EndpointID != joined.Endpoint.ID {
		t.Fatal("authenticated heartbeat changed the original Endpoint or binding")
	}
	endpoint, err := persistence.GetEndpointV2(joined.Endpoint.ID)
	if err != nil {
		t.Fatal(err)
	}
	// A future housekeeping cutoff deterministically makes the legacy
	// last_seen old while the real, renewed binding lease remains live.
	cutoff := time.Now().UTC().Add(time.Minute)
	lease, err := time.Parse(time.RFC3339Nano, renewed.LeaseExpiresAt)
	lastSeen, lastSeenErr := time.Parse(time.RFC3339Nano, endpoint.LastSeen)
	if err != nil || lastSeenErr != nil || !lease.After(cutoff) || !lastSeen.Before(cutoff) {
		t.Fatal("test did not establish stale legacy presence with a live binding")
	}
	stale, err := persistence.MarkStaleEndpoints(cutoff.Format(time.RFC3339Nano))
	if err != nil || len(stale) != 0 {
		t.Fatalf("housekeeping selected a live leased Endpoint: ids=%v err=%v", stale, err)
	}
	endpoint, err = persistence.GetEndpointV2(joined.Endpoint.ID)
	if err != nil || endpoint == nil || endpoint.Status != "online" {
		t.Fatalf("live leased Endpoint was marked offline: endpoint=%#v err=%v", endpoint, err)
	}
	after, err := service.AuthenticateForGroup(joined.SessionToken, group.ID)
	if err != nil || after.BindingID != first.BindingID || after.BindingEpoch != first.BindingEpoch {
		t.Fatalf("original Session stopped authenticating after housekeeping: actor=%#v err=%v", after, err)
	}
	if _, err := service.RenewForGroup(joined.SessionToken, group.ID, 0); err != nil {
		t.Fatalf("original Session could not heartbeat after housekeeping: %v", err)
	}
}

func TestExpiredOrLeftSessionStillFailsAfterPresenceHousekeeping(t *testing.T) {
	t.Run("expired lease", func(t *testing.T) {
		service, persistence, group := newFabricTestService(t)
		joined, err := service.Join(JoinInput{GroupID: group.ID, PrincipalName: "expired",
			Harness: "codex", NativeSessionID: "native-expired", NodeID: "node-expired"})
		if err != nil {
			t.Fatal(err)
		}
		actor, err := service.AuthenticateForGroup(joined.SessionToken, group.ID)
		if err != nil {
			t.Fatal(err)
		}
		past := time.Now().UTC().Add(-time.Minute).Format(time.RFC3339Nano)
		if _, err := persistence.RenewSessionBindingLease(actor.BindingID, actor.LeaseOwner,
			actor.BindingEpoch, past); err != nil {
			t.Fatal(err)
		}
		if _, err := persistence.MarkStaleEndpoints(time.Now().UTC().Add(time.Minute).Format(time.RFC3339Nano)); err != nil {
			t.Fatal(err)
		}
		if _, err := service.AuthenticateForGroup(joined.SessionToken, group.ID); !errors.Is(err, ErrUnauthenticated) {
			t.Fatalf("expired binding authenticated: %v", err)
		}
		if _, err := service.RenewForGroup(joined.SessionToken, group.ID, 0); !errors.Is(err, ErrUnauthenticated) {
			t.Fatalf("expired binding renewed: %v", err)
		}
	})
	t.Run("left Endpoint", func(t *testing.T) {
		service, persistence, group := newFabricTestService(t)
		joined, err := service.Join(JoinInput{GroupID: group.ID, PrincipalName: "left",
			Harness: "codex", NativeSessionID: "native-left", NodeID: "node-left"})
		if err != nil {
			t.Fatal(err)
		}
		actor, err := service.AuthenticateForGroup(joined.SessionToken, group.ID)
		if err != nil {
			t.Fatal(err)
		}
		if err := service.Leave(actor, "test leave"); err != nil {
			t.Fatal(err)
		}
		if _, err := persistence.MarkStaleEndpoints(time.Now().UTC().Add(time.Minute).Format(time.RFC3339Nano)); err != nil {
			t.Fatal(err)
		}
		endpoint, err := persistence.GetEndpointV2(joined.Endpoint.ID)
		if err != nil || endpoint == nil || endpoint.Status != "left" {
			t.Fatalf("Endpoint did not leave: endpoint=%#v err=%v", endpoint, err)
		}
		if _, err := service.AuthenticateForGroup(joined.SessionToken, group.ID); !errors.Is(err, ErrUnauthenticated) {
			t.Fatalf("left Endpoint authenticated: %v", err)
		}
		if _, err := service.RenewForGroup(joined.SessionToken, group.ID, 0); !errors.Is(err, ErrUnauthenticated) {
			t.Fatalf("left Endpoint renewed: %v", err)
		}
	})
}
