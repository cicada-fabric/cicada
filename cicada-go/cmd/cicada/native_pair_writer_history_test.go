package main

import (
	"context"
	"errors"
	"net/http"
	"reflect"
	"testing"

	"github.com/cicada-ai/cicada/internal/fabric"
	"github.com/cicada-ai/cicada/internal/nodeinbox"
	"github.com/cicada-ai/cicada/internal/nodekeys"
	"github.com/cicada-ai/cicada/internal/nodelock"
)

// These cases exercise the real drain caller, durable physical writer and a
// queue subprocess. They use the existing legacy Group fixture, so they prove
// preservation of writer history, not Native Pair dual-consent activation.
func TestNativePairConsumerDrainRetainsOriginalWriterAfterCurrentDenial(t *testing.T) {
	for _, outcome := range []nodelock.NativeOutcomeState{nodelock.NativeQueueAccepted, nodelock.NativeUncertain} {
		for _, stage := range []string{"early-http-denial", "writer-current-http-denial", "early-independent-owner-revocation"} {
			t.Run(string(outcome)+"/"+stage, func(t *testing.T) {
				f := newNativeDeliveryRelayFixture(t)
				claim, entry := f.claim(t)
				op, err := machineRelayNativeOperation(f.ctx, claim, entry)
				if err != nil {
					t.Fatal(err)
				}
				if outcome == nodelock.NativeUncertain {
					f.process.QueueExit = 2
					nativeDeliverySaveConfig(t, f.process)
				}
				err = executeMachineNativeCodex(f.ctx, claim.SessionID, "SYNTHETIC_ORIGINAL_WRITER_HISTORY", op, f.nativeScope)
				var uncertain *nativeInjectionUncertainError
				if outcome == nodelock.NativeQueueAccepted && err != nil || outcome == nodelock.NativeUncertain && !errors.As(err, &uncertain) {
					t.Fatalf("original queue did not produce expected durable history: %v", err)
				}
				before := nativeDeliveryAuditRecords(t, f.process.Root)
				ctx := f.ctx
				switch stage {
				case "early-http-denial":
					f.guardStatus.Store(http.StatusForbidden)
				case "writer-current-http-denial":
					ctx = context.WithValue(ctx, machineNativeDeliveryLifecycleKey{}, machineNativeDeliveryLifecycle{
						command: nativeDeliveryQueueCommand(f.process.ConfigPath), observe: func(phase string) {
							if phase == "writer_wait" {
								f.guardStatus.Store(http.StatusForbidden)
							}
						},
					})
				case "early-independent-owner-revocation":
					auth, err := fetchCrossNodeGroupDeliveryAuthorization(ctx, f.local.hub.URL, f.local.nodeID, entry.MessageID, entry.AttemptID)
					if err != nil {
						t.Fatal(err)
					}
					state, err := nodekeys.OpenCryptoState(machineNodeStateDir(f.local.stateDir, f.local.nodeID))
					if err != nil {
						t.Fatal(err)
					}
					grant := auth.Sender.Grant
					trust, err := state.GetNodeOwnerKeyTrustLocal(grant.OwnerID, grant.OwnerKeyID)
					if err == nil {
						_, err = state.RevokeNodeOwnerKeyTrustLocal(grant.OwnerID, grant.OwnerKeyID, trust.Version)
					}
					closeErr := state.Close()
					if err != nil || closeErr != nil {
						t.Fatalf("local revoke: %v %v", err, closeErr)
					}
				}
				err = f.drain(ctx, claim, entry)
				var historical *machineNativeHistoricalOutcomeError
				if !errors.As(err, &historical) || historical.Outcome != outcome {
					t.Fatalf("current denial rewrote original outcome: %v", err)
				}
				stored, err := f.inbox.Get(f.ctx, f.messageID)
				if err != nil || stored.State != nodeinbox.NODE_RECEIVED || f.journal.entry(f.messageID) == nil {
					t.Fatalf("original inbox/journal changed: %#v %v", stored, err)
				}
				if !reflect.DeepEqual(before, nativeDeliveryAuditRecords(t, f.process.Root)) || nativeDeliveryCount(t, f.process.CounterPath) != 1 {
					t.Fatal("current denial rewrote writer history or queued again")
				}
				if !reflect.DeepEqual(f.layers(), []string{fabric.ReceiptNodeReceived}) {
					t.Fatalf("current denial fabricated a terminal receipt: %v", f.layers())
				}
			})
		}
	}
}
