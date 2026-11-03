package main

import (
	"context"
	"errors"
	"flag"
	"io"
	"os"
	"os/signal"
	"syscall"

	"github.com/cicada-ai/cicada/internal/e2ee"
	wire "github.com/cicada-ai/cicada/internal/hubaccountwire"
	"github.com/cicada-ai/cicada/internal/nodelock"
	"github.com/mattn/go-isatty"
)

func machineNodePairingCodeCommand(args []string, output io.Writer) error {
	flags := flag.NewFlagSet("machine pairing-code", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	id := flags.String("id", "", "original Node ID")
	stateDir := flags.String("state-dir", "", "original private Node state directory")
	if flags.Parse(args) != nil || len(flags.Args()) != 0 || *id == "" || *stateDir == "" {
		return errors.New("usage: cicada machine pairing-code --id NODE_ID --state-dir DIR")
	}
	out, ok := output.(*os.File)
	if !ok || out == nil || !isatty.IsTerminal(out.Fd()) || !isatty.IsTerminal(os.Stdin.Fd()) {
		return errors.New("pairing code requires an interactive input and output TTY")
	}
	maintenance, e := nodelock.AcquireMaintenance(*stateDir, *id)
	if e != nil {
		return e
	}
	defer maintenance.Close()
	keyPath, _ := machineNodeControlPaths(*stateDir, *id)
	raw, e := machineNodePairPrivateRead(keyPath, machineNodePairLocalMax)
	if e != nil {
		return e
	}
	identity, e := e2ee.UnmarshalIdentity(raw)
	clear(raw)
	if e != nil {
		return errMachineNodePairState
	}
	profile, e := machineNodePairSavedProfile(*stateDir, *id)
	if e != nil {
		return e
	}
	if profile == "scoped" {
		s, e := loadMachineNodePairScopedState(*stateDir, *id, identity)
		if e != nil {
			return e
		}
		defer clear(s.Secret)
		if s.Stage != wire.NodePairTrustScopedPending && s.Stage != "PINNED" {
			return errMachineNodePairPending
		}
		return machineNodePairScopedDisplayCode(s, output)
	}
	return errMachineNodePairLegacyUnsupported
}

func prepareMachineNodePairTrust(parent context.Context, stateDir, nodeID, name, address, expectedOrigin string, explicitOrigin, once, retry bool, output io.Writer, completed *bool, profiles ...string) error {
	if machineNodePairNoSymlinkPath(machineNodeStateDir(stateDir, nodeID)) != nil {
		return errMachineNodePairState
	}
	writer, e := nodelock.AcquireWriterRoot(stateDir)
	if e != nil {
		return e
	}
	defer writer.Close()
	agent, e := nodelock.AcquireAgent(stateDir, nodeID)
	if e != nil {
		return e
	}
	defer agent.Close()
	if e = rejectMachineRecoveryMutation(stateDir, stateDir, nodeID); e != nil {
		return e
	}
	if e = rejectMachineNodePendingRecovery(stateDir, nodeID); e != nil {
		return e
	}
	ctx, stop := signal.NotifyContext(parent, syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	requested := "auto"
	if len(profiles) > 0 {
		requested = profiles[0]
	}
	profile, descriptorText, e := selectMachineNodePairProfile(ctx, stateDir, nodeID, address, expectedOrigin, explicitOrigin, requested)
	if e != nil {
		return e
	}
	if profile == "scoped" {
		return runMachineNodePairScopedTrust(ctx, stateDir, nodeID, name, address, expectedOrigin, explicitOrigin, once, retry, output, completed, descriptorText)
	}
	return errMachineNodePairLegacyUnsupported
}
