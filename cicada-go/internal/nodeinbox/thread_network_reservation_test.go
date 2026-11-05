package nodeinbox

import (
	"bufio"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"reflect"
	"sort"
	"sync"
	"testing"
	"time"
)

func reservationInput() ThreadNetworkReservationInput {
	return ThreadNetworkReservationInput{AccountID: "SYNTHETIC-verified-account", Harness: "codex", NativeSessionID: "SYNTHETIC-original-native-thread", HubID: "SYNTHETIC-hub-a", NetworkID: "SYNTHETIC-network-a", OperationID: "SYNTHETIC-original-join", RequestDigest: reservationDigest("SYNTHETIC-original-packet")}
}
func reservationDigest(text string) string {
	d := sha256.Sum256([]byte(text))
	return hex.EncodeToString(d[:])
}
func reservationAccepted(in ThreadNetworkReservationInput) NativeContextScopeInput {
	return NativeContextScopeInput{AccountID: in.AccountID, Harness: in.Harness, NativeSessionID: in.NativeSessionID, HubID: in.HubID, NetworkID: in.NetworkID, EndpointID: "SYNTHETIC-real-endpoint", BindingID: "SYNTHETIC-real-binding", BindingEpoch: 7}
}
func reservationOpen(t *testing.T, path string) *NativeContextRegistry {
	t.Helper()
	r, e := OpenNativeContextRegistry(path)
	if e != nil {
		t.Fatal(e)
	}
	t.Cleanup(func() { _ = r.Close() })
	return r
}
func reservationInspect(t *testing.T, r *NativeContextRegistry, in ThreadNetworkReservationInput) *ThreadNetworkInspection {
	t.Helper()
	v, e := r.InspectThreadNetwork(context.Background(), in.AccountID, in.Harness, in.NativeSessionID)
	if e != nil {
		t.Fatal(e)
	}
	return v
}
func reservationClaim(t *testing.T, r *NativeContextRegistry, in ThreadNetworkReservationInput) *ThreadNetworkReservation {
	t.Helper()
	v, e := r.ReserveThreadNetwork(context.Background(), in)
	if e != nil {
		t.Fatal(e)
	}
	return v
}

// Canonical metadata snapshots catch same-count mutations and exclude nothing:
// these three metadata tables contain neither transport counters nor heartbeats.
func reservationMetadata(t *testing.T, r *NativeContextRegistry) []byte {
	t.Helper()
	all := make(map[string][]string)
	for _, table := range []string{"node_native_context_history_v1", "node_thread_network_authority_v1", "node_thread_network_reservations_v1"} {
		rows, e := r.db.Query("SELECT * FROM " + table)
		if e != nil {
			t.Fatal(e)
		}
		cols, e := rows.Columns()
		if e != nil {
			t.Fatal(e)
		}
		for rows.Next() {
			values, targets := make([]any, len(cols)), make([]any, len(cols))
			for i := range values {
				targets[i] = &values[i]
			}
			if e = rows.Scan(targets...); e != nil {
				t.Fatal(e)
			}
			raw, e := json.Marshal(values)
			if e != nil {
				t.Fatal(e)
			}
			all[table] = append(all[table], string(raw))
		}
		if e = rows.Err(); e != nil {
			t.Fatal(e)
		}
		rows.Close()
		sort.Strings(all[table])
	}
	raw, e := json.Marshal(all)
	if e != nil {
		t.Fatal(e)
	}
	return raw
}
func reservationNoMutation(t *testing.T, r *NativeContextRegistry, action func() error, want error) {
	t.Helper()
	before := reservationMetadata(t, r)
	if e := action(); !errors.Is(e, want) {
		t.Fatalf("wanted closed error %v, got %v", want, e)
	}
	if !bytes.Equal(before, reservationMetadata(t, r)) {
		t.Fatal("refused operation changed registry metadata")
	}
}

func TestThreadNetworkReservationUnknownSurvivesRestartAndSettlesOriginal(t *testing.T) {
	ctx := context.Background()
	path := nativeContextHistoryTestPath(t)
	r := reservationOpen(t, path)
	in := reservationInput()
	if v := reservationInspect(t, r, in); v.State != ThreadNetworkUnassigned || v.Revision != 0 {
		t.Fatal("fresh identity was assigned")
	}
	claim := reservationClaim(t, r, in)
	if claim.State != ThreadNetworkReserved || claim.Revision != 1 {
		t.Fatal("first reservation shape")
	}
	var count int
	if e := r.db.QueryRow(`SELECT count(*) FROM node_native_context_history_v1`).Scan(&count); e != nil || count != 0 {
		t.Fatal("pre-admission reservation fabricated Endpoint/Binding")
	}
	before := reservationMetadata(t, r)
	retry := reservationClaim(t, r, in)
	if !reflect.DeepEqual(claim, retry) || !bytes.Equal(before, reservationMetadata(t, r)) {
		t.Fatal("exact reservation retry mutated metadata")
	}
	other := in
	other.HubID, other.NetworkID, other.OperationID = "SYNTHETIC-hub-b", "SYNTHETIC-network-b", "SYNTHETIC-other-join"
	reservationNoMutation(t, r, func() error { _, e := r.ReserveThreadNetwork(ctx, other); return e }, ErrNativeContextScopeConflict)
	parallel := in
	parallel.OperationID += "-another"
	reservationNoMutation(t, r, func() error { _, e := r.ReserveThreadNetwork(ctx, parallel); return e }, ErrThreadNetworkUnresolved)
	unknown, e := r.MarkThreadNetworkUnresolved(ctx, *claim)
	if e != nil || unknown.State != ThreadNetworkUnresolved || unknown.Revision != 2 {
		t.Fatal("lost response did not retain unresolved original", e)
	}
	if e = r.Close(); e != nil {
		t.Fatal(e)
	}
	r = reservationOpen(t, path)
	if v := reservationInspect(t, r, in); !reflect.DeepEqual(v, unknown) {
		t.Fatal("cold reopen changed pending original")
	}
	if retry = reservationClaim(t, r, in); retry.ReservationID != claim.ReservationID || retry.Revision != claim.Revision || retry.State != ThreadNetworkUnresolved {
		t.Fatal("retry minted a new reservation")
	}
	observed := reservationAccepted(in)
	reservationNoMutation(t, r, func() error { _, e := r.CheckAndRecordNetworkEnrollmentContext(ctx, observed); return e }, ErrThreadNetworkUnresolved)
	accepted := ThreadNetworkSettlement{Authenticated: true, ResponseDigest: reservationDigest("SYNTHETIC authenticated accepted response"), Accepted: &observed}
	v, e := r.SettleThreadNetwork(ctx, *claim, accepted)
	if e != nil || v.State != ThreadNetworkCurrent || v.HubID != in.HubID || v.NetworkID != in.NetworkID || v.Revision != 3 {
		t.Fatal("authenticated original did not settle", e)
	}
	before = reservationMetadata(t, r)
	again, e := r.SettleThreadNetwork(ctx, *claim, accepted)
	if e != nil || !reflect.DeepEqual(v, again) || !bytes.Equal(before, reservationMetadata(t, r)) {
		t.Fatal("settlement retry changed original", e)
	}
	if raw := reservationMetadata(t, r); bytes.Contains(raw, []byte(in.NativeSessionID)) || bytes.Contains(raw, []byte(in.AccountID)) {
		t.Fatal("registry persisted raw native SID/account")
	}
	accepted.ResponseDigest = reservationDigest("SYNTHETIC substituted response")
	reservationNoMutation(t, r, func() error { _, e := r.SettleThreadNetwork(ctx, *claim, accepted); return e }, ErrThreadNetworkOriginalConflict)
	reservationNoMutation(t, r, func() error { _, e := r.ReserveThreadNetwork(ctx, other); return e }, ErrNativeContextScopeConflict)
}

func TestThreadNetworkReservationRequiresAuthenticatedNoEffectAndKeepsHistory(t *testing.T) {
	for _, assigned := range []bool{false, true} {
		t.Run(fmt.Sprint(assigned), func(t *testing.T) {
			ctx := context.Background()
			r := reservationOpen(t, nativeContextHistoryTestPath(t))
			in := reservationInput()
			if assigned {
				accepted := reservationAccepted(in)
				if _, e := r.CheckAndRecordNetworkEnrollmentContext(ctx, accepted); e != nil {
					t.Fatal(e)
				}
				in.ExpectedRevision = 1
			}
			claim := reservationClaim(t, r, in)
			for _, evidence := range []ThreadNetworkSettlement{{NoEffect: true}, {Authenticated: true, NoEffect: true}, {Authenticated: true, ResponseDigest: reservationDigest("SYNTHETIC reply")}, {Authenticated: true, NoEffect: true, Accepted: func() *NativeContextScopeInput { v := reservationAccepted(in); return &v }(), ResponseDigest: reservationDigest("SYNTHETIC reply")}} {
				reservationNoMutation(t, r, func() error { _, e := r.SettleThreadNetwork(ctx, *claim, evidence); return e }, ErrThreadNetworkEvidenceInvalid)
			}
			noEffect := ThreadNetworkSettlement{Authenticated: true, NoEffect: true, ResponseDigest: reservationDigest("SYNTHETIC authenticated original refusal")}
			v, e := r.SettleThreadNetwork(ctx, *claim, noEffect)
			if e != nil {
				t.Fatal(e)
			}
			if assigned && v.State != ThreadNetworkCurrent || !assigned && v.State != ThreadNetworkUnassigned {
				t.Fatal("no-effect erased established history or invented an assignment")
			}
			before := reservationMetadata(t, r)
			if _, e = r.SettleThreadNetwork(ctx, *claim, noEffect); e != nil || !bytes.Equal(before, reservationMetadata(t, r)) {
				t.Fatal("no-effect retry changed metadata", e)
			}
			if old := reservationClaim(t, r, in); old.State != ThreadNetworkNoEffect || old.ReservationID != claim.ReservationID {
				t.Fatal("old no-effect request was revived")
			}
			other := in
			other.HubID, other.NetworkID, other.OperationID, other.ExpectedRevision = "SYNTHETIC-hub-b", "SYNTHETIC-network-b", "SYNTHETIC-next-join", v.Revision
			if assigned {
				reservationNoMutation(t, r, func() error { _, e := r.ReserveThreadNetwork(ctx, other); return e }, ErrNativeContextScopeConflict)
			} else {
				second := reservationClaim(t, r, other)
				pending := reservationMetadata(t, r)
				if _, e = r.SettleThreadNetwork(ctx, *claim, noEffect); e != nil || !bytes.Equal(pending, reservationMetadata(t, r)) {
					t.Fatal("old no-effect reply cleared a successor reservation", e)
				}
				if got := reservationInspect(t, r, other); got.Reservation == nil || got.Reservation.ReservationID != second.ReservationID {
					t.Fatal("successor reservation lost")
				}
			}
		})
	}
}

func TestThreadNetworkReservationCASIdentityAndOriginalConflicts(t *testing.T) {
	ctx := context.Background()
	r := reservationOpen(t, nativeContextHistoryTestPath(t))
	in := reservationInput()
	bad := in
	bad.ExpectedRevision = 1
	reservationNoMutation(t, r, func() error { _, e := r.ReserveThreadNetwork(ctx, bad); return e }, ErrThreadNetworkRevisionConflict)
	claim := reservationClaim(t, r, in)
	for _, change := range []string{"digest", "scope", "expected", "account"} {
		t.Run(change, func(t *testing.T) {
			bad := in
			want := ErrThreadNetworkOriginalConflict
			switch change {
			case "digest":
				bad.RequestDigest = reservationDigest("SYNTHETIC other packet")
			case "scope":
				bad.NetworkID += "-other"
			case "expected":
				bad.ExpectedRevision = claim.Revision
			case "account":
				bad.AccountID = "SYNTHETIC false account declaration"
				want = ErrNativeContextScopeConflict
			}
			reservationNoMutation(t, r, func() error { _, e := r.ReserveThreadNetwork(ctx, bad); return e }, want)
		})
	}
	observed := reservationAccepted(in)
	observed.EndpointID = ""
	reservationNoMutation(t, r, func() error {
		_, e := r.SettleThreadNetwork(ctx, *claim, ThreadNetworkSettlement{Authenticated: true, ResponseDigest: reservationDigest("SYNTHETIC response"), Accepted: &observed})
		return e
	}, ErrThreadNetworkEvidenceInvalid)
	second := in
	second.NativeSessionID = "SYNTHETIC independent Thread"
	second.HubID, second.NetworkID = "SYNTHETIC-hub-b", "SYNTHETIC-network-b"
	if c := reservationClaim(t, r, second); c.HubID != second.HubID {
		t.Fatal("registry applied a machine-wide Network quota")
	}
}

func TestThreadNetworkReservationConcurrentSQLiteHandlesHaveOneWinner(t *testing.T) {
	for _, sameNetwork := range []bool{false, true} {
		t.Run(fmt.Sprint(sameNetwork), func(t *testing.T) {
			path := nativeContextHistoryTestPath(t)
			a, b := reservationOpen(t, path), reservationOpen(t, path)
			first, second := reservationInput(), reservationInput()
			second.OperationID += "-second"
			if !sameNetwork {
				second.HubID, second.NetworkID = "SYNTHETIC-hub-b", "SYNTHETIC-network-b"
			}
			start := make(chan struct{})
			var wg sync.WaitGroup
			var outcomes [2]error
			for i, r := range []*NativeContextRegistry{a, b} {
				wg.Add(1)
				go func(i int, r *NativeContextRegistry) {
					defer wg.Done()
					<-start
					in := first
					if i == 1 {
						in = second
					}
					_, outcomes[i] = r.ReserveThreadNetwork(context.Background(), in)
				}(i, r)
			}
			close(start)
			wg.Wait()
			wins := 0
			for _, e := range outcomes {
				if e == nil {
					wins++
				} else if !errors.Is(e, ErrNativeContextScopeConflict) && !errors.Is(e, ErrThreadNetworkUnresolved) {
					t.Fatal("unrelated contention failure", e)
				}
			}
			var history, claims int
			if e := a.db.QueryRow(`SELECT count(*) FROM node_native_context_history_v1`).Scan(&history); e != nil {
				t.Fatal(e)
			}
			if e := a.db.QueryRow(`SELECT count(*) FROM node_thread_network_reservations_v1`).Scan(&claims); e != nil {
				t.Fatal(e)
			}
			if wins != 1 || claims != 1 || history != 0 {
				t.Fatalf("wins=%d claims=%d fabricated history=%d", wins, claims, history)
			}
		})
	}
}

func TestThreadNetworkLegacyConflictsAreReadOnlyAndDoNotChooseFirstScope(t *testing.T) {
	for _, kind := range []string{"two-networks", "unknown-network", "changed-account"} {
		t.Run(kind, func(t *testing.T) {
			ctx := context.Background()
			r := reservationOpen(t, nativeContextHistoryTestPath(t))
			in := reservationInput()
			source := reservationAccepted(in)
			_, identity, account, e := normalizeNativeContextScopeInput(source)
			if e != nil {
				t.Fatal(e)
			}
			for i := 0; i < 2; i++ {
				network, ac := in.NetworkID, account
				if i == 1 {
					switch kind {
					case "two-networks":
						network += "-other"
					case "unknown-network":
						network = ""
					case "changed-account":
						ac = reservationDigest("SYNTHETIC different account")
					}
				}
				_, e = r.db.Exec(`INSERT INTO node_native_context_history_v1 VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?)`, fmt.Sprint("SYNTHETIC-old-row-", i), identity, ac, in.Harness, in.HubID, network, fmt.Sprint("SYNTHETIC-group-", i), NativeContextPolicyGroupScoped, source.EndpointID, source.BindingID, uint64(i+1), 1, 1)
				if e != nil {
					t.Fatal(e)
				}
			}
			before := reservationMetadata(t, r)
			v := reservationInspect(t, r, in)
			if v.State != ThreadNetworkConflict || v.HubID != "" || v.NetworkID != "" {
				t.Fatal("legacy conflict selected a winning scope")
			}
			if !bytes.Equal(before, reservationMetadata(t, r)) {
				t.Fatal("Inspect rewrote legacy evidence")
			}
			reservationNoMutation(t, r, func() error { _, e := r.ReserveThreadNetwork(ctx, in); return e }, ErrNativeContextScopeConflict)
			reservationNoMutation(t, r, func() error { _, e := r.CheckAndRecordNetworkEnrollmentContext(ctx, source); return e }, ErrNativeContextScopeConflict)
		})
	}
}

func TestThreadNetworkReservationBoundsPreserveExactOriginal(t *testing.T) {
	r, e := openNativeContextRegistry(":memory:", 1, 1)
	if e != nil {
		t.Fatal(e)
	}
	defer r.Close()
	in := reservationInput()
	claim := reservationClaim(t, r, in)
	if got := reservationClaim(t, r, in); got.ReservationID != claim.ReservationID {
		t.Fatal("capacity evicted pending original")
	}
	noEffect := ThreadNetworkSettlement{Authenticated: true, NoEffect: true, ResponseDigest: reservationDigest("SYNTHETIC refusal")}
	v, e := r.SettleThreadNetwork(context.Background(), *claim, noEffect)
	if e != nil {
		t.Fatal(e)
	}
	newRequest := in
	newRequest.OperationID += "-new"
	newRequest.ExpectedRevision = v.Revision
	reservationNoMutation(t, r, func() error { _, e := r.ReserveThreadNetwork(context.Background(), newRequest); return e }, ErrNativeContextHistoryAtLimit)
	if got := reservationClaim(t, r, in); got.State != ThreadNetworkNoEffect {
		t.Fatal("capacity erased original no-effect receipt")
	}
}

// Independent processes use separate registry handles and no shared Go mutex.
// Both stop at a pipe barrier after opening the same private on-disk database.
func TestThreadNetworkReservationConcurrentProcessesHaveOneWinner(t *testing.T) {
	if path := os.Getenv("CICADA_SYNTHETIC_THREAD_RESERVATION_CHILD"); path != "" {
		r := reservationOpen(t, path)
		fmt.Fprintln(os.Stdout, "READY")
		if _, err := bufio.NewReader(os.Stdin).ReadByte(); err != nil {
			t.Fatal(err)
		}
		in := reservationInput()
		in.OperationID += os.Getenv("CICADA_SYNTHETIC_THREAD_RESERVATION_SUFFIX")
		if os.Getenv("CICADA_SYNTHETIC_THREAD_RESERVATION_OTHER_NETWORK") == "1" {
			in.HubID, in.NetworkID = "SYNTHETIC-hub-b", "SYNTHETIC-network-b"
		}
		_, err := r.ReserveThreadNetwork(context.Background(), in)
		switch {
		case err == nil:
			fmt.Fprintln(os.Stdout, "WINNER")
		case errors.Is(err, ErrNativeContextScopeConflict), errors.Is(err, ErrThreadNetworkUnresolved):
			fmt.Fprintln(os.Stdout, "FENCED")
		default:
			t.Fatal(err)
		}
		return
	}
	for _, sameNetwork := range []bool{false, true} {
		t.Run(fmt.Sprint(sameNetwork), func(t *testing.T) {
			path := nativeContextHistoryTestPath(t)
			r := reservationOpen(t, path)
			type child struct {
				cmd    *exec.Cmd
				input  io.WriteCloser
				output *bufio.Reader
				stderr bytes.Buffer
			}
			children := make([]*child, 0, 2)
			for i := 0; i < 2; i++ {
				ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
				defer cancel()
				c := &child{cmd: exec.CommandContext(ctx, os.Args[0], "-test.run", "^TestThreadNetworkReservationConcurrentProcessesHaveOneWinner$")}
				c.cmd.Env = append(os.Environ(), "CICADA_SYNTHETIC_THREAD_RESERVATION_CHILD="+path, "CICADA_SYNTHETIC_THREAD_RESERVATION_SUFFIX="+fmt.Sprint(i))
				if i == 1 && !sameNetwork {
					c.cmd.Env = append(c.cmd.Env, "CICADA_SYNTHETIC_THREAD_RESERVATION_OTHER_NETWORK=1")
				}
				pipe, err := c.cmd.StdoutPipe()
				if err != nil {
					t.Fatal(err)
				}
				c.output = bufio.NewReader(pipe)
				c.input, err = c.cmd.StdinPipe()
				if err != nil {
					t.Fatal(err)
				}
				c.cmd.Stderr = &c.stderr
				if err = c.cmd.Start(); err != nil {
					t.Fatal(err)
				}
				// If an assertion fails before Wait, stop only this owned child.
				defer func() {
					if c.cmd.ProcessState == nil {
						_ = c.cmd.Process.Kill()
						_ = c.cmd.Wait()
					}
				}()
				line, err := c.output.ReadString('\n')
				if err != nil || line != "READY\n" {
					t.Fatalf("child not ready: %q %v %s", line, err, c.stderr.String())
				}
				children = append(children, c)
			}
			for _, c := range children {
				if _, err := c.input.Write([]byte("x")); err != nil {
					t.Fatal(err)
				}
				_ = c.input.Close()
			}
			wins, fenced := 0, 0
			for _, c := range children {
				raw, err := io.ReadAll(io.LimitReader(c.output, nativeContextChildStdoutLimit))
				if err != nil {
					t.Fatal(err)
				}
				if err = c.cmd.Wait(); err != nil {
					t.Fatalf("child: %v %s %s", err, raw, c.stderr.String())
				}
				wins += bytes.Count(raw, []byte("WINNER\n"))
				fenced += bytes.Count(raw, []byte("FENCED\n"))
			}
			if wins != 1 || fenced != 1 {
				t.Fatalf("wins=%d fenced=%d", wins, fenced)
			}
			v := reservationInspect(t, r, reservationInput())
			if v.State != ThreadNetworkReserved || v.Reservation == nil {
				t.Fatalf("missing durable winner: %#v", v)
			}
			var history, claims int
			if err := r.db.QueryRow(`SELECT count(*) FROM node_native_context_history_v1`).Scan(&history); err != nil {
				t.Fatal(err)
			}
			if err := r.db.QueryRow(`SELECT count(*) FROM node_thread_network_reservations_v1`).Scan(&claims); err != nil {
				t.Fatal(err)
			}
			if history != 0 || claims != 1 {
				t.Fatalf("fabricated history=%d claims=%d", history, claims)
			}
		})
	}
}
