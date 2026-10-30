package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/cicada-ai/cicada/internal/nodeinbox"
	"github.com/cicada-ai/cicada/internal/nodelock"
)

func sealedPhaseRecords(t *testing.T, data []byte) []machineSealedPhaseRecord {
	t.Helper()
	var records []machineSealedPhaseRecord
	for _, line := range bytes.Split(bytes.TrimSpace(data), []byte{'\n'}) {
		if len(line) == 0 {
			continue
		}
		if len(line) > 2048 {
			t.Fatal("phase line exceeded its bound")
		}
		var record machineSealedPhaseRecord
		if err := json.Unmarshal(line, &record); err != nil {
			t.Fatal(err)
		}
		records = append(records, record)
	}
	return records
}

func TestMachineSealedPhaseDefaultOff(t *testing.T) {
	for _, optIn := range []string{"", "true", "0"} {
		t.Run("opt_in_"+optIn, func(t *testing.T) {
			t.Setenv("CICADA_NODE_SEALED_PHASE_DEBUG", optIn)
			var log bytes.Buffer
			var phases []string
			ctx := context.WithValue(context.Background(), machineSealedPhaseWriterKey{}, &log)
			ctx = context.WithValue(ctx, machineNativeDeliveryLifecycleKey{}, machineNativeDeliveryLifecycle{
				observe: func(phase string) { phases = append(phases, phase) },
			})
			observedCtx, observer := newMachineSealedPhaseContext(ctx, nodeinbox.Claim{}, machineRelayJournalEntry{})
			if observer != nil || observedCtx != ctx || newMachineSealedPhaseObserver(ctx, nodeinbox.Claim{}, machineRelayJournalEntry{}) != nil {
				t.Fatal("default-off allocated an observer or replaced context")
			}
			observer.enter("CRYPTO_READ")
			observer.finish(errors.New("PUBLIC_SYNTHETIC_SECRET"))
			machineNativeDeliveryDependencies(observedCtx).observed("writer_wait")
			if log.Len() != 0 || !reflect.DeepEqual(phases, []string{"writer_wait"}) {
				t.Fatal("default-off changed logging or the original observer")
			}
		})
	}
}

func TestMachineSealedPhaseBoundAndPrivacy(t *testing.T) {
	t.Setenv("CICADA_NODE_SEALED_PHASE_DEBUG", "1")
	var log bytes.Buffer
	claim := nodeinbox.Claim{Delivery: nodeinbox.Delivery{
		MessageID: "public_message", EndpointID: "bad\nPUBLIC_SYNTHETIC_SECRET",
		AttemptID: strings.Repeat("x", 193), SessionID: "public_native_sid",
	}}
	ctx := context.WithValue(context.Background(), machineSealedPhaseWriterKey{}, &log)
	_, observer := newMachineSealedPhaseContext(ctx, claim, machineRelayJournalEntry{RequestID: "bad secret value", AttemptID: "public_remote_attempt"})
	for i := 0; i < 40; i++ {
		observer.enter("CRYPTO_READ")
		observer.finish(fmt.Errorf("PUBLIC_SYNTHETIC_SECRET body/key/token: %w", context.DeadlineExceeded))
	}
	records := sealedPhaseRecords(t, log.Bytes())
	if len(records) != machineSealedPhaseLimit || bytes.Contains(log.Bytes(), []byte("PUBLIC_SYNTHETIC_SECRET")) || bytes.Contains(log.Bytes(), []byte("bad secret")) {
		t.Fatal("phase count or privacy bound failed")
	}
	for i, record := range records {
		if record.Event != "NODE_SEALED_PHASE" || record.MessageID != claim.MessageID || record.NativeSID != claim.SessionID ||
			record.EndpointID != "" || record.AttemptID != "" || record.RequestID != "" || record.RemoteAttemptID != "public_remote_attempt" || record.Phase != "CRYPTO_READ" {
			t.Fatal("unsafe or incorrect identifier projection")
		}
		if i%2 == 0 && (record.State != "BEGIN" || record.ErrorClass != "NONE") ||
			i%2 == 1 && (record.State != "ERROR" || record.ErrorClass != "TIMEOUT") {
			t.Fatal("error text replaced the closed phase classification")
		}
	}
}

func TestMachineSealedPhaseErrorClasses(t *testing.T) {
	cases := []struct {
		err  error
		want string
	}{
		{nil, "NONE"}, {context.Canceled, "CANCELLED"}, {context.DeadlineExceeded, "TIMEOUT"},
		{&machineAPIError{StatusCode: http.StatusForbidden, Body: "PUBLIC_SYNTHETIC_SECRET"}, "AUTH_REJECTED"},
		{&machineAPIError{StatusCode: http.StatusConflict, Body: "PUBLIC_SYNTHETIC_SECRET"}, "AUTHORITY_INVALID"},
		{&machineAPIError{StatusCode: http.StatusGone}, "NOT_FOUND"},
		{os.ErrPermission, "LOCAL_PERMISSION"}, {os.ErrNotExist, "LOCAL_NOT_FOUND"},
		{errors.New("PUBLIC_SYNTHETIC_SECRET"), "UNCLASSIFIED"},
	}
	for _, tc := range cases {
		if got := machineSealedPhaseError(tc.err); got != tc.want {
			t.Fatalf("closed class = %s, want %s", got, tc.want)
		}
	}
	var log bytes.Buffer
	observer := &machineSealedPhaseObserver{writer: &log}
	observer.enter("CRYPTO_READ")
	observer.reject()
	records := sealedPhaseRecords(t, log.Bytes())
	if records[1].ErrorClass != "LOCAL_REJECTED" {
		t.Fatal("local rejection was misclassified as a remote HTTP rejection")
	}
}

type sealedPhaseFailingWriter struct{ calls int }

func (w *sealedPhaseFailingWriter) Write([]byte) (int, error) {
	w.calls++
	return 0, io.ErrClosedPipe
}

func TestMachineSealedPhaseLoggingFailure(t *testing.T) {
	t.Setenv("CICADA_NODE_SEALED_PHASE_DEBUG", "1")
	f := newN2RouteFixture(t, false)
	claim, entry := f.claim(t)
	writer := &sealedPhaseFailingWriter{}
	ctx := context.WithValue(f.ctx, machineSealedPhaseWriterKey{}, writer)
	if err := f.drain(ctx, claim, entry); err != nil {
		t.Fatal("logging failure changed the original successful drain")
	}
	if writer.calls != 17 || nativeDeliveryCount(t, f.process.CounterPath) != 1 {
		t.Fatal("logging failure changed phase or queue execution count")
	}
}

func TestMachineSealedPhaseLinkDrainOrder(t *testing.T) {
	t.Setenv("CICADA_NODE_SEALED_PHASE_DEBUG", "1")
	f := newN2RouteFixture(t, false)
	claim, entry := f.claim(t)
	var log bytes.Buffer
	ctx := context.WithValue(f.ctx, machineSealedPhaseWriterKey{}, &log)
	dependencies := machineNativeDeliveryDependencies(ctx)
	var originalPhases []string
	dependencies.observe = func(phase string) { originalPhases = append(originalPhases, phase) }
	ctx = context.WithValue(ctx, machineNativeDeliveryLifecycleKey{}, dependencies)
	if err := f.drain(ctx, claim, entry); err != nil {
		t.Fatal(err)
	}
	var phases []string
	for _, record := range sealedPhaseRecords(t, log.Bytes()) {
		if record.ErrorClass != "NONE" || record.MessageID != claim.MessageID || record.AttemptID != claim.AttemptID || record.RemoteAttemptID != entry.AttemptID {
			t.Fatal("successful drain emitted an error or wrong attempt")
		}
		phases = append(phases, record.Phase+":"+record.State)
	}
	want := []string{"CLAIM_ROUTE:BEGIN", "CLAIM_ROUTE:END", "AUTHORITY_HTTP:BEGIN", "AUTHORITY_HTTP:END",
		"CRYPTO_READ:BEGIN", "CRYPTO_READ:END", "SEALED_VALIDATE:BEGIN", "LOCAL_CONTEXT:BEGIN", "LOCAL_CONTEXT:END",
		"SEALED_VALIDATE:END", "OPERATION_SCOPE:BEGIN", "OPERATION_SCOPE:END", "WRITER_WAIT:BEGIN", "WRITER_WAIT:END",
		"QUEUE_WAIT:END", "QUEUE_DURABLE:END", "WRITER_CLOSED:END"}
	if !reflect.DeepEqual(phases, want) || !reflect.DeepEqual(originalPhases, []string{"writer_wait", "queue_wait_succeeded", "accepted_durable", "accepted_writer_closed"}) {
		t.Fatalf("unexpected phase order: %v, original %v", phases, originalPhases)
	}
}

func TestMachineSealedPhaseWriterWaitError(t *testing.T) {
	t.Setenv("CICADA_NODE_SEALED_PHASE_DEBUG", "1")
	f := newN2RouteFixture(t, false)
	claim, entry := f.claim(t)
	held, err := nodelock.AcquireNativeWriter(f.ctx, f.process.Root, f.process.WriterScope, "codex", claim.SessionID)
	if err != nil {
		t.Fatal(err)
	}
	defer held.Close()
	var log bytes.Buffer
	ctx := context.WithValue(f.ctx, machineSealedPhaseWriterKey{}, &log)
	ctx, cancel := context.WithTimeout(ctx, time.Second)
	defer cancel()
	if err := f.drain(ctx, claim, entry); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatal("busy writer did not preserve its original deadline error")
	}
	records := sealedPhaseRecords(t, log.Bytes())
	last := records[len(records)-1]
	if last.Phase != "WRITER_WAIT" || last.State != "ERROR" || last.ErrorClass != "TIMEOUT" || nativeDeliveryCount(t, f.process.CounterPath) != 0 {
		t.Fatal("writer wait observation claimed queue execution or lost the timeout")
	}
}

func TestMachineSealedPhaseFabricPreDrainFailure(t *testing.T) {
	t.Setenv("CICADA_NODE_SEALED_PHASE_DEBUG", "1")
	t.Setenv("CICADA_NODE_TOKEN", "synthetic-phase-token")
	t.Setenv("CICADA_NODE_TOKEN_FILE", "")
	paths := []string{
		"/v2/relay/nodes/synthetic-phase-node/sealed/claim",
		"/v2/relay/nodes/synthetic-phase-node/group/sealed/claim",
		"/v2/fabric/node/networks/direct/claim",
		"/v2/relay/nodes/synthetic-phase-node/claim",
	}
	for index, phase := range []string{"SEALED_CLAIM", "GROUP_CLAIM", "NETWORK_CLAIM", "PLAIN_CLAIM"} {
		t.Run(phase, func(t *testing.T) {
			var visited []string
			var visitsMu sync.Mutex
			hub := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				visitsMu.Lock()
				visited = append(visited, r.URL.Path)
				visitsMu.Unlock()
				if r.URL.Path == paths[index] {
					http.Error(w, "PUBLIC_SYNTHETIC_SECRET", http.StatusServiceUnavailable)
					return
				}
				w.Header().Set("Content-Type", "application/json")
				_, _ = io.WriteString(w, `{"deliveries":[]}`)
			}))
			defer hub.Close()
			root := t.TempDir()
			inbox, err := nodeinbox.Open(machineNodeInboxPath(root, "synthetic-phase-node"))
			if err != nil {
				t.Fatal(err)
			}
			defer inbox.Close()
			var log bytes.Buffer
			ctx := pinnedNativeTestHubContext(context.Background(), "hub_synthetic_phase", "synthetic-phase-node", root, hub.URL, "synthetic-phase-token")
			ctx = context.WithValue(ctx, machineSealedPhaseWriterKey{}, &log)
			err = processPinnedTestMachineFabricDeliveries(ctx, hub.URL, "synthetic-phase-node", inbox, root)
			visitsMu.Lock()
			defer visitsMu.Unlock()
			if !machineAPIHasStatus(err, http.StatusServiceUnavailable) || !reflect.DeepEqual(visited, paths[:index+1]) {
				t.Fatalf("unexpected original short circuit: error_class=%s visited=%q", machineSealedPhaseError(err), visited)
			}
			records := sealedPhaseRecords(t, log.Bytes())
			last := records[len(records)-1]
			if last.Phase != phase || last.State != "ERROR" || last.ErrorClass != "UNCLASSIFIED" || bytes.Contains(log.Bytes(), []byte("PUBLIC_SYNTHETIC_SECRET")) {
				t.Fatal("pre-drain failure lost its closed stage or exposed error text")
			}
			for _, record := range records {
				if record.MessageID != "" || record.RequestID != "" || record.EndpointID != "" || record.AttemptID != "" || record.RemoteAttemptID != "" || record.NativeSID != "" {
					t.Fatal("poll observer invented claim coordinates")
				}
			}
		})
	}
}

func TestMachineSealedPhaseFabricGroupDrain(t *testing.T) {
	t.Setenv("CICADA_NODE_SEALED_PHASE_DEBUG", "1")
	f := newNativeDeliveryRelayFixture(t)
	var log bytes.Buffer
	ctx := context.WithValue(f.ctx, machineSealedPhaseWriterKey{}, &log)
	dependencies := machineNativeDeliveryDependencies(ctx)
	var callbacks []string
	dependencies.observe = func(phase string) { callbacks = append(callbacks, phase) }
	ctx = context.WithValue(ctx, machineNativeDeliveryLifecycleKey{}, dependencies)
	if err := processPinnedTestMachineFabricDeliveries(ctx, f.local.hub.URL, f.local.nodeID, f.inbox, f.local.stateDir); err != nil {
		t.Fatal("observed original Group drain failed", err)
	}
	var poll, drain []machineSealedPhaseRecord
	for _, record := range sealedPhaseRecords(t, log.Bytes()) {
		if record.State == "ERROR" || record.ErrorClass != "NONE" {
			t.Fatal("successful Group delivery was reported as a failure")
		}
		if record.MessageID == "" {
			if record.RequestID != "" || record.EndpointID != "" || record.AttemptID != "" || record.RemoteAttemptID != "" || record.NativeSID != "" {
				t.Fatal("poll observer borrowed a child claim")
			}
			poll = append(poll, record)
		} else {
			if record.MessageID != f.messageID || record.EndpointID != f.local.targetMCP.endpointID || record.NativeSID != f.local.nativeB || record.AttemptID == "" || record.RemoteAttemptID == "" {
				t.Fatal("Group observer lost original claim coordinates")
			}
			drain = append(drain, record)
		}
	}
	if len(poll) != 26 || len(drain) == 0 || len(drain) > machineSealedPhaseLimit || poll[len(poll)-1].Phase != "INBOX_DRAIN" || poll[len(poll)-1].State != "END" {
		t.Fatal("poll and exact-attempt phase lifecycles are incomplete")
	}
	var queuePhases []string
	for _, record := range drain {
		if record.Phase == "QUEUE_WAIT" || record.Phase == "QUEUE_DURABLE" || record.Phase == "WRITER_CLOSED" {
			queuePhases = append(queuePhases, record.Phase+":"+record.State)
		}
	}
	if !reflect.DeepEqual(queuePhases, []string{"QUEUE_WAIT:END", "QUEUE_DURABLE:END", "WRITER_CLOSED:END"}) || !reflect.DeepEqual(callbacks, []string{"writer_wait", "queue_wait_succeeded", "accepted_durable", "accepted_writer_closed"}) || nativeDeliveryCount(t, f.process.CounterPath) != 1 {
		t.Fatal("poll/drain duplicated a callback or confused writer wait with accepted queue")
	}
}

func TestMachineSealedPhaseGroupAuthorityFailure(t *testing.T) {
	t.Setenv("CICADA_NODE_SEALED_PHASE_DEBUG", "1")
	f := newNativeDeliveryRelayFixture(t)
	claim, entry := f.claim(t)
	f.guardUnavailable.Store(true)
	var log bytes.Buffer
	ctx := context.WithValue(f.ctx, machineSealedPhaseWriterKey{}, &log)
	if err := f.drain(ctx, claim, entry); !machineAPIHasStatus(err, http.StatusServiceUnavailable) {
		t.Fatal("diagnostics changed the original retryable authority failure")
	}
	records := sealedPhaseRecords(t, log.Bytes())
	last := records[len(records)-1]
	if last.Phase != "AUTHORITY_HTTP" || last.State != "ERROR" || last.ErrorClass != "UNCLASSIFIED" || nativeDeliveryCount(t, f.process.CounterPath) != 0 {
		t.Fatal("authority outage was mistaken for a native queue attempt")
	}
	delivery, err := f.inbox.Get(f.ctx, claim.MessageID)
	if err != nil || delivery.State != nodeinbox.NODE_RECEIVED || delivery.ConsumerID != "" || f.journal.entry(claim.MessageID) == nil {
		t.Fatal("observed temporary failure lost its original recoverable claim")
	}
}
