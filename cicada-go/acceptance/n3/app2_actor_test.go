package n3_test

import (
	"context"
	"io"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"testing"
	"time"

	"github.com/cicada-ai/cicada/internal/appcore"
)

// These are private fixture messages, not a proposed Hub enrollment protocol.
// The isolated actor receives no Owner/activation material or App1 profile.
type app2Input struct {
	RequestID      string   `json:"request_id"`
	ProbeAddress   string   `json:"probe_address"`
	ProbeSHA256    string   `json:"probe_sha256"`
	ForbiddenPaths []string `json:"forbidden_paths"`
}

type app2Ready struct {
	RequestID     string           `json:"request_id"`
	BinarySHA256  string           `json:"binary_sha256"`
	ProbeVerified bool             `json:"probe_verified"`
	DeniedPaths   []string         `json:"denied_paths"`
	Current       appcore.Snapshot `json:"current"`
}

type app2Command struct {
	appActorCommand
	Stop bool `json:"stop"`
}

func TestN3App2Process(t *testing.T) {
	if os.Getenv("CICADA_N3_APP2_CHILD") != "1" {
		t.Skip("entry point requires the owned isolated App2 container")
	}
	const profile, mailbox = "/app2/profile", "/app2/io"
	var input app2Input
	readJSON(t, filepath.Join(mailbox, "start.json"), &input)
	host, _, err := net.SplitHostPort(input.ProbeAddress)
	if err != nil || net.ParseIP(host) == nil || !net.ParseIP(host).IsLoopback() {
		t.Fatal("App2 probe must use literal fixture loopback")
	}
	conn, err := net.DialTimeout("tcp", input.ProbeAddress, 5*time.Second)
	if err != nil {
		t.Fatal("App2 cannot reach the owned fixture network")
	}
	_ = conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	probe := make([]byte, 32)
	_, err = io.ReadFull(conn, probe)
	conn.Close()
	if err != nil || hash(probe) != input.ProbeSHA256 {
		t.Fatal("App2 network probe does not match the owned fixture")
	}
	clear(probe)
	ready := app2Ready{RequestID: input.RequestID, ProbeVerified: true}
	for _, path := range input.ForbiddenPaths {
		if !filepath.IsAbs(path) {
			t.Fatal("App2 denied-path probe is not absolute")
		}
		file, openErr := os.Open(path)
		if openErr == nil {
			file.Close()
			t.Fatal("App2 can open another actor's state or host control path")
		}
		if !os.IsNotExist(openErr) && !os.IsPermission(openErr) {
			t.Fatal("App2 denied-path probe has an unclassified result")
		}
		ready.DeniedPaths = append(ready.DeniedPaths, path)
	}
	root := filepath.Join(profile, "vaults")
	c := must(appcore.NewController(appcore.Config{HTTP: appcore.NewHTTPClient(),
		OpenVault: syntheticVaultOpener(root), DiscoverVaults: appcore.NewProfileDiscovery(root), AllowLoopbackHTTP: true}))
	defer c.Close()
	if c.Dispatch(context.Background(), appcore.Action{Kind: appcore.ActionDiscoverProfiles}) != nil {
		t.Fatal("actual isolated App Controller cannot inspect its empty profile")
	}
	ready.Current = c.Snapshot()
	if len(ready.Current.Profiles) != 0 || ready.Current.Account.LocalOwnerKeyPresent || ready.Current.Authorization.Confirmed {
		t.Fatal("new isolated App2 inherited another profile or authorization")
	}
	binary := must(os.ReadFile(must(os.Executable())))
	ready.BinarySHA256 = hash(binary)
	clear(binary)
	writeJSON(t, filepath.Join(mailbox, "ready.json"), ready)
	for sequence := 1; ; sequence++ {
		base := filepath.Join(mailbox, "command-"+strconv.Itoa(sequence))
		deadline := time.Now().Add(90 * time.Second)
		for {
			if _, err := os.Stat(base + ".json"); err == nil {
				break
			} else if !os.IsNotExist(err) || time.Now().After(deadline) {
				t.Fatal("isolated App2 command unavailable before its bounded deadline")
			}
			time.Sleep(10 * time.Millisecond)
		}
		var command app2Command
		readJSON(t, base+".json", &command)
		if command.Stop {
			return // Controller.Close runs before the host records process exit.
		}
		if command.ClockOffsetSeconds != 0 || (command.Action != nil &&
			(command.Action.Kind == appcore.ActionGenerateOwner || command.Action.Kind == appcore.ActionImportOwner)) {
			t.Fatal("App2 fixture cannot substitute its clock or load Owner signing keys")
		}
		reply := appActorReply{ClockMode: "WALL_CLOCK"}
		if command.Action != nil {
			reply.ActionFailed = c.Dispatch(context.Background(), *command.Action) != nil
			if reply.ActionFailed {
				reply.ActionError = "OTHER"
			}
		}
		reply.Current = c.Snapshot()
		if reply.Current.Account.LocalOwnerKeyPresent {
			t.Fatal("isolated App2 unexpectedly acquired an Owner signing key")
		}
		writeJSON(t, base+"-reply.json", reply)
	}
}
