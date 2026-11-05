package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"github.com/cicada-ai/cicada/internal/nodeinbox"
)

type machineThreadNetworkAdmission struct {
	hub   machineHubContext
	claim *nodeinbox.ThreadNetworkReservation
}

// Called only after the existing native verifier, before the first external
// Network-linked mutation. It reserves no fake Endpoint, Binding or identity.
func reserveMachineThreadNetwork(ctx context.Context, runtime, sid, network, operation string, body []byte, retained *nodeinbox.ThreadNetworkReservation) (*machineThreadNetworkAdmission, error) {
	hub, ok := machineHubFrom(ctx)
	if !ok || hub.NativeContexts == nil || hub.HubID == "" || hub.WriterScope == "" {
		return nil, errors.New("verified shared Thread Network registry is unavailable")
	}
	sum := sha256.Sum256(append([]byte("cicada/native-thread/network-original/v1\x00"), body...))
	digest := hex.EncodeToString(sum[:])
	view, err := hub.NativeContexts.InspectThreadNetwork(ctx, hub.WriterScope, runtime, sid)
	if err != nil {
		return nil, err
	}
	expected := view.Revision
	if retained != nil {
		if retained.Revision == 0 || retained.HubID != hub.HubID || retained.NetworkID != network || retained.OperationID != operation || retained.RequestDigest != digest {
			return nil, nodeinbox.ErrThreadNetworkOriginalConflict
		}
		expected = retained.Revision - 1
	} else if view.Reservation != nil && view.Reservation.OperationID == operation && view.Reservation.RequestDigest == digest {
		expected = view.Reservation.Revision - 1
	}
	claim, err := hub.NativeContexts.ReserveThreadNetwork(ctx, nodeinbox.ThreadNetworkReservationInput{AccountID: hub.WriterScope, Harness: runtime, NativeSessionID: sid, HubID: hub.HubID, NetworkID: network, OperationID: operation, RequestDigest: digest, ExpectedRevision: expected})
	if err != nil {
		return nil, err
	}
	if claim.State == nodeinbox.ThreadNetworkNoEffect {
		return nil, errors.New("original Network admission was closed without effects")
	}
	return &machineThreadNetworkAdmission{hub: hub, claim: claim}, nil
}
func (a *machineThreadNetworkAdmission) unresolved(ctx context.Context) {
	if a == nil || a.claim == nil || a.claim.State == nodeinbox.ThreadNetworkAccepted {
		return
	}
	_, _ = a.hub.NativeContexts.MarkThreadNetworkUnresolved(ctx, *a.claim)
}

// The transport/result verifier must already have checked all real source
// coordinates. Only an authenticated exact original response reaches here.
func (a *machineThreadNetworkAdmission) accepted(ctx context.Context, scope nodeinbox.NativeContextScopeInput, response []byte) error {
	if a == nil || a.claim == nil || len(response) == 0 {
		return nodeinbox.ErrThreadNetworkEvidenceInvalid
	}
	if scope.AccountID != a.hub.WriterScope || scope.HubID != a.claim.HubID || scope.NetworkID != a.claim.NetworkID {
		return nodeinbox.ErrThreadNetworkEvidenceInvalid
	}
	sum := sha256.Sum256(response)
	_, err := a.hub.NativeContexts.SettleThreadNetwork(ctx, *a.claim, nodeinbox.ThreadNetworkSettlement{Authenticated: true, ResponseDigest: hex.EncodeToString(sum[:]), Accepted: &scope})
	return err
}

func checkMachineThreadNetworkCurrent(ctx context.Context, runtime, sid, network string) error {
	hub, ok := machineHubFrom(ctx)
	if !ok || hub.NativeContexts == nil || hub.HubID == "" || hub.WriterScope == "" {
		return nodeinbox.ErrThreadNetworkUnresolved
	}
	v, err := hub.NativeContexts.InspectThreadNetwork(ctx, hub.WriterScope, runtime, sid)
	if err != nil {
		return err
	}
	if v.State != nodeinbox.ThreadNetworkCurrent {
		return nodeinbox.ErrThreadNetworkUnresolved
	}
	if v.HubID != hub.HubID || v.NetworkID != network {
		return nodeinbox.ErrNativeContextScopeConflict
	}
	return nil
}
